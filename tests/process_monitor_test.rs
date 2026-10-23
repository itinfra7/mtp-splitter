//! 소켓 스냅숏의 임대·충돌·네이티브 수집과 선택적인 실제 SOCKET 감시를 검증한다.

use mtp_splitter::{
    packet::Protocol,
    process_tracker::{ActiveSocketTable, Ownership, SocketBinding, SocketKey, SocketOwner},
};

fn key() -> SocketKey {
    SocketKey {
        protocol: Protocol::Udp,
        local: "0.0.0.0:45000".parse().unwrap(),
    }
}
fn binding(pid: u32) -> SocketBinding {
    SocketBinding {
        key: key(),
        pid,
        creation_time: 100,
    }
}

#[test]
fn snapshot_wildcard_ownership_expires_without_direct_identity_guessing() {
    let table = ActiveSocketTable::default();
    table.replace_snapshot(&[binding(42)], 100, 1000).unwrap();
    assert_eq!(
        table.owner(Protocol::Udp, "10.0.0.2:45000".parse().unwrap(), 1099),
        Ownership::Known(42)
    );
    assert_eq!(
        table.owner(Protocol::Udp, key().local, 1100),
        Ownership::Unknown
    );
    table.evict(1100).unwrap();
    assert_eq!(
        table.owner(Protocol::Udp, key().local, 1101),
        Ownership::Unknown
    );
}

#[test]
fn snapshot_conflict_with_live_event_is_ambiguous_until_replaced() {
    let table = ActiveSocketTable::default();
    table
        .register(
            key(),
            SocketOwner {
                endpoint_id: u64::MAX,
                pid: 42,
                creation_time: 100,
                close_after_ms: None,
            },
        )
        .unwrap();
    table.replace_snapshot(&[binding(43)], 0, 1000).unwrap();
    assert_eq!(
        table.owner(Protocol::Udp, key().local, 0),
        Ownership::Ambiguous
    );
    table
        .replace_snapshot(&[binding(42), binding(42)], 1, 1000)
        .unwrap();
    assert_eq!(
        table.owner(Protocol::Udp, key().local, 1),
        Ownership::Known(42)
    );
    table.replace_snapshot(&[], 2, 1000).unwrap();
    assert_eq!(
        table.owner(Protocol::Udp, key().local, 2),
        Ownership::Known(42)
    );
    table.close(u64::MAX, 2).unwrap();
    table.evict(2002).unwrap();
    assert_eq!(
        table.owner(Protocol::Udp, key().local, 2002),
        Ownership::Unknown
    );
}

#[test]
fn invalid_snapshot_never_overwrites_previous_generation() {
    let table = ActiveSocketTable::default();
    table.replace_snapshot(&[binding(42)], 0, 1000).unwrap();
    assert!(table.replace_snapshot(&[binding(0)], 1, 1000).is_err());
    assert!(table.replace_snapshot(&[], 1, 0).is_err());
    assert!(table.replace_snapshot(&[], 1, 5001).is_err());
    assert_eq!(
        table.owner(Protocol::Udp, key().local, 2),
        Ownership::Known(42)
    );
}

#[test]
fn child_inherits_when_previously_tracked_parent_exits_between_snapshots() {
    use mtp_splitter::{
        config::ProcessRule,
        process_tracker::{ProcessIdentity, ProcessTracker},
    };
    let rules = vec![ProcessRule {
        exe_name: Some("launcher.exe".into()),
        path_glob: None,
        sha256: None,
        include_children: true,
    }];
    let mut tracker = ProcessTracker::new(rules, []).unwrap();
    let parent = ProcessIdentity {
        pid: 1,
        parent: 0,
        creation_time: 10,
        image: "launcher.exe".into(),
    };
    let child = ProcessIdentity {
        pid: 2,
        parent: 1,
        creation_time: 20,
        image: "helper.exe".into(),
    };
    tracker.refresh(&[parent]).unwrap();
    tracker.refresh(std::slice::from_ref(&child)).unwrap();
    assert!(tracker.get(1).is_none());
    assert!(tracker.get(2).unwrap().inherit);
    let grandchild = ProcessIdentity {
        pid: 3,
        parent: 2,
        creation_time: 30,
        image: "worker.exe".into(),
    };
    tracker.refresh(&[child, grandchild]).unwrap();
    assert!(tracker.get(3).unwrap().inherit);
}

#[test]
fn exited_parent_policy_does_not_cross_pid_reuse_or_creation_order() {
    use mtp_splitter::{
        config::ProcessRule,
        process_tracker::{ProcessIdentity, ProcessTracker},
    };
    for reused in [true, false] {
        let rules = vec![ProcessRule {
            exe_name: Some("launcher.exe".into()),
            path_glob: None,
            sha256: None,
            include_children: true,
        }];
        let mut tracker = ProcessTracker::new(rules, []).unwrap();
        tracker
            .refresh(&[ProcessIdentity {
                pid: 1,
                parent: 0,
                creation_time: 10,
                image: "launcher.exe".into(),
            }])
            .unwrap();
        let mut next = vec![ProcessIdentity {
            pid: 2,
            parent: 1,
            creation_time: if reused { 30 } else { 5 },
            image: "helper.exe".into(),
        }];
        if reused {
            next.push(ProcessIdentity {
                pid: 1,
                parent: 0,
                creation_time: 20,
                image: "other.exe".into(),
            });
        }
        tracker.refresh(&next).unwrap();
        assert!(tracker.get(2).is_none());
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use anyhow::{Context, Result, ensure};
    use mtp_splitter::{
        config::ProcessRule,
        nat_engine::{NatSessionTable, TunnelStatus},
        packet,
        packet_router::{Decision, NetworkPath, PacketRouter},
        paths::AppPaths,
        platform::{divert::DivertApi, driver_service, monitor::ProcessMonitor, socket_snapshot},
        process_tracker::SocketOwnership,
    };
    use std::{
        net::{TcpListener, TcpStream, UdpSocket},
        os::windows::process::CommandExt,
        path::PathBuf,
        process::{Child, Command, Stdio},
        sync::Arc,
        time::{Duration, Instant},
    };

    #[test]
    fn ip_helper_sees_existing_ipv4_and_ipv6_tcp_udp_sockets() {
        for ip in ["127.0.0.1", "::1"] {
            let listener = TcpListener::bind((ip, 0)).unwrap();
            let connected = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (accepted, _) = listener.accept().unwrap();
            let udp = UdpSocket::bind((ip, 0)).unwrap();
            let rows = socket_snapshot::snapshot().unwrap();
            for (protocol, local) in [
                (Protocol::Tcp, listener.local_addr().unwrap()),
                (Protocol::Tcp, connected.local_addr().unwrap()),
                (Protocol::Tcp, accepted.local_addr().unwrap()),
                (Protocol::Udp, udp.local_addr().unwrap()),
            ] {
                assert!(
                    rows.iter().any(|row| row.pid == std::process::id()
                        && row.key == SocketKey { protocol, local }),
                    "스냅숏에 소켓 {protocol:?} {local}이 없습니다"
                );
            }
        }
    }

    struct KernelSession {
        paths: AppPaths,
        api: Arc<DivertApi>,
        _lock: std::fs::File,
    }
    impl KernelSession {
        fn new() -> Result<Self> {
            let paths = AppPaths::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")))?;
            let lock = paths.lock()?;
            let api = DivertApi::load(&paths)?;
            Ok(Self {
                paths,
                api,
                _lock: lock,
            })
        }
    }
    impl Drop for KernelSession {
        fn drop(&mut self) {
            if let Err(error) = driver_service::cleanup_idle(&self.paths, &self.api) {
                eprintln!("시험 후 드라이버 정리 실패: {error:#}");
            }
        }
    }
    fn router() -> Arc<PacketRouter> {
        Arc::new(PacketRouter::new(
            Arc::new(NatSessionTable::new(100, 17001, 17002)),
            Arc::new(ActiveSocketTable::default()),
            Arc::new(TunnelStatus::default()),
            [],
        ))
    }
    fn rules(children: bool) -> Vec<ProcessRule> {
        vec![ProcessRule {
            exe_name: Some(
                std::env::current_exe()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            ),
            path_glob: None,
            sha256: None,
            include_children: children,
        }]
    }
    fn wait_until(monitor: &ProcessMonitor, condition: impl Fn() -> bool) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            monitor.healthy()?;
            if condition() {
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "감시 상태가 제한 시간 안에 반영되지 않았습니다"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    #[ignore = "관리자 권한과 앱 bin의 실제 WinDivert를 사용하는 커널 통합 시험"]
    fn monitor_bootstraps_old_sockets_and_consumes_new_socket_events() -> Result<()> {
        let session = KernelSession::new()?;
        let old_socket = UdpSocket::bind("127.0.0.1:0")?;
        let router = router();
        let started = Instant::now();
        let monitor =
            ProcessMonitor::start(&session.api, Arc::clone(&router), rules(true), [], started)?;
        assert_eq!(
            router.sockets.owner(
                Protocol::Udp,
                old_socket.local_addr()?,
                started.elapsed().as_millis() as u64
            ),
            Ownership::Known(std::process::id())
        );
        let baseline = monitor
            .counters
            .socket_events
            .load(std::sync::atomic::Ordering::Relaxed);
        let new_socket = UdpSocket::bind("127.0.0.1:0")?;
        let new_local = new_socket.local_addr()?;
        new_socket.connect(old_socket.local_addr()?)?;
        new_socket.send(b"socket-event")?;
        wait_until(&monitor, || {
            monitor
                .counters
                .socket_events
                .load(std::sync::atomic::Ordering::Relaxed)
                > baseline
                && matches!(router.sockets.event_owner_identity(
                    Protocol::Udp,
                        new_local,
                    started.elapsed().as_millis() as u64,
                    ), SocketOwnership::Known { pid, .. } if pid == std::process::id())
        })?;
        assert!(
            monitor
                .snapshot()?
                .tracked_pids
                .contains(&std::process::id())
        );
        drop(new_socket);
        wait_until(&monitor, || {
            router.sockets.event_owner_identity(
                Protocol::Udp,
                new_local,
                started.elapsed().as_millis() as u64,
            ) == SocketOwnership::Unknown
        })?;
        Ok(())
    }

    struct Fixture {
        child: Child,
        executable: PathBuf,
    }
    impl Fixture {
        fn spawn(port: u16) -> Result<Self> {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("runtime/tmp")
                .join(format!(
                    "monitor-fixture-{}-{}.exe",
                    std::process::id(),
                    rand::random::<u64>()
                ));
            std::fs::copy(std::env::current_exe()?, &path)?;
            let child = Command::new(&path)
                .args(["--ignored", "--exact", "windows::monitor_child_fixture"])
                .env("MTP_SPLITTER_MONITOR_FIXTURE_PORT", port.to_string())
                .creation_flags(0x08000000)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            Ok(Self {
                child,
                executable: path,
            })
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
            }
            let _ = self.child.wait();
            let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .canonicalize()
                .unwrap();
            if let Ok(path) = self.executable.canonicalize() {
                assert!(path.starts_with(workspace.join("runtime/tmp")));
                std::fs::remove_file(path).unwrap();
            }
        }
    }

    #[test]
    #[ignore = "관리자 권한의 부모 시험이 별도 이름의 자식 실행 파일에서만 호출하는 소켓 피어"]
    fn monitor_child_fixture() -> Result<()> {
        let port: u16 = std::env::var("MTP_SPLITTER_MONITOR_FIXTURE_PORT")
            .context("부모 시험의 포트가 필요합니다")?
            .parse()?;
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(10)))?;
        socket.connect(("127.0.0.1", port))?;
        socket.send(b"monitor-child")?;
        let mut response = [0; 16];
        let length = socket.recv(&mut response)?;
        ensure!(
            &response[..length] == b"done",
            "부모의 시험 종료 응답이 다릅니다"
        );
        Ok(())
    }

    #[test]
    #[ignore = "관리자 권한에서 실제 자식 프로세스 상속과 제외 정책을 검사하는 커널 통합 시험"]
    fn monitor_inherits_child_pid_only_when_rule_enables_children() -> Result<()> {
        let session = KernelSession::new()?;
        for children in [true, false] {
            let receiver = UdpSocket::bind("127.0.0.1:0")?;
            receiver.set_read_timeout(Some(Duration::from_secs(5)))?;
            let router = router();
            let started = Instant::now();
            let monitor = ProcessMonitor::start(
                &session.api,
                Arc::clone(&router),
                rules(children),
                [],
                started,
            )?;
            let mut fixture = Fixture::spawn(receiver.local_addr()?.port())?;
            let pid = fixture.child.id();
            let mut buffer = [0; 32];
            let (length, peer) = receiver.recv_from(&mut buffer)?;
            assert_eq!(&buffer[..length], b"monitor-child");
            let bytes = packet::udp(peer, "192.0.2.1:9".parse()?, b"classification-only")?;
            wait_until(&monitor, || {
                router
                    .sockets
                    .owner(Protocol::Udp, peer, started.elapsed().as_millis() as u64)
                    == Ownership::Known(pid)
                    && match router.decide(
                        &bytes,
                        true,
                        NetworkPath {
                            interface: 1,
                            sub_interface: 0,
                        },
                        started.elapsed().as_millis() as u64,
                    ) {
                        Decision::Inject {
                            outbound: false, ..
                        } => children && monitor.snapshot().unwrap().tracked_pids.contains(&pid),
                        Decision::Pass => !children,
                        _ => false,
                    }
            })?;
            let action = router.decide(
                &bytes,
                true,
                NetworkPath {
                    interface: 1,
                    sub_interface: 0,
                },
                started.elapsed().as_millis() as u64,
            );
            if children {
                assert!(matches!(
                    action,
                    Decision::Inject {
                        outbound: false,
                        ..
                    }
                ));
            } else {
                assert_eq!(action, Decision::Pass);
            }
            receiver.send_to(b"done", peer)?;
            ensure!(
                fixture.child.wait()?.success(),
                "자식 시험 프로세스가 실패했습니다"
            );
            drop(fixture);
            drop(monitor);
        }
        Ok(())
    }
}
