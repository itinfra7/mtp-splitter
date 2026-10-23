//! 운영 실행 경로의 실제 커널 NAT·인증 터널·메인 충돌·신규 소켓 차단을 검증한다.
//! 공개 테스트 인증서와 문서용 목적지만 사용하고 최하위 캡처로 외부 전송을 막는다.

#[cfg(windows)]
mod support;

#[cfg(windows)]
mod windows {
    use super::support::{self, Directory, TestGatewayIo};
    use anyhow::{Context, Result, ensure};
    use mtp_splitter::{
        config::ProcessRule,
        fake_dns,
        nat_engine::TunnelState,
        packet,
        paths::AppPaths,
        platform::{
            divert::{DivertApi, DivertHandle},
            driver_service, guard_lock,
            runtime::{self, RunOptions},
        },
        protocol::{Frame, FrameType, Settings, Target, TargetAddress},
        shared_state::SharedState,
        transport,
        watchdog::{self, RelayPorts},
    };
    use std::{
        fs::{self, File},
        io::{Read, Write},
        net::{Shutdown, SocketAddr, TcpStream, UdpSocket},
        os::windows::process::CommandExt,
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        sync::{Arc, Mutex},
        thread,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0},
        System::Threading::{OpenProcess, WaitForSingleObject},
    };

    fn workspace() -> Result<AppPaths> {
        AppPaths::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")))
    }

    #[test]
    fn relay_exemption_filter_is_compiled_and_matches_only_reserved_paths() -> Result<()> {
        let api = DivertApi::load(&workspace()?)?;
        let ports = RelayPorts {
            tcp: 17001,
            udp: 17002,
        };
        let filter = ports.guard_filter()?;
        api.validate_filter(&filter, 0)?;
        let mut address = mtp_splitter::platform::divert::Address::default();
        address.set_outbound(true);
        for (source, target, expected) in [
            ("127.0.0.2:20000", "127.0.0.1:17002", false),
            ("127.0.0.1:17002", "127.0.0.2:20000", false),
            ("[::1]:20000", "[::1]:17002", false),
            ("127.0.0.2:20000", "127.0.0.1:17003", true),
            ("10.0.0.2:20000", "192.0.2.1:17002", true),
        ] {
            let bytes = packet::udp(source.parse()?, target.parse()?, b"filter")?;
            address.bits =
                (address.bits & !(1 << 20)) | (u32::from(packet::parse(&bytes)?.ipv6) << 20);
            assert_eq!(api.matches(&filter, &bytes, &address)?, expected);
        }
        assert!(RelayPorts { tcp: 0, udp: 1 }.guard_filter().is_err());
        Ok(())
    }

    #[test]
    fn watchdog_lock_prevents_shared_state_reset_and_idle_cleanup_preserves_writer() -> Result<()> {
        let dir = Directory::new();
        let lock = guard_lock::root_lock(&dir.paths)?;
        assert!(guard_lock::root_lock(&dir.paths).is_err());
        let mut writer = SharedState::open(&dir.paths, true)?;
        writer.publish(&[], TunnelState::Down, 42)?;
        assert!(!mtp_splitter::shared_state::remove_idle(&dir.paths)?);
        assert_eq!(
            SharedState::open(&dir.paths, false)?
                .snapshot()?
                .heartbeat_ms,
            42
        );
        drop(writer);
        assert!(mtp_splitter::shared_state::remove_idle(&dir.paths)?);
        drop(lock);
        drop(guard_lock::root_lock(&dir.paths)?);
        Ok(())
    }

    async fn send(
        io: &mut TestGatewayIo,
        kind: FrameType,
        id: u32,
        payload: Vec<u8>,
    ) -> Result<()> {
        transport::write_frame(
            io,
            &Frame {
                kind,
                stream_id: id,
                payload,
            },
        )
        .await
    }
    async fn echo_gateway(mut io: TestGatewayIo) -> Result<()> {
        loop {
            let frame = transport::read_frame(&mut io).await?;
            match frame.kind {
                FrameType::OpenTcp | FrameType::OpenUdp => {
                    let (target, consumed) = Target::decode(&frame.payload)?;
                    ensure!(
                        consumed == frame.payload.len(),
                        "목적지 헤더 뒤에 불필요한 데이터가 있습니다"
                    );
                    match frame.kind {
                        FrameType::OpenTcp => ensure!(
                            target
                                == Target {
                                    address: TargetAddress::Ip("192.0.2.1".parse()?),
                                    port: 18080
                                }
                                || target
                                    == Target {
                                        address: TargetAddress::Ip("::1".parse()?),
                                        port: 18082
                                    },
                            "TCP 목적지가 다릅니다"
                        ),
                        _ => ensure!(
                            target
                                == Target {
                                    address: TargetAddress::Domain("kernel.example".into()),
                                    port: 19000
                                }
                                || target
                                    == Target {
                                        address: TargetAddress::Ip("::1".parse()?),
                                        port: 19002
                                    },
                            "UDP 목적지 또는 Fake-IP 원격 도메인이 다릅니다"
                        ),
                    }
                    let endpoint = Target {
                        address: TargetAddress::Ip("127.0.0.1".parse()?),
                        port: 40000,
                    }
                    .encode()?;
                    let mut payload = endpoint;
                    payload.extend(
                        Target {
                            address: match &target.address {
                                TargetAddress::Ip(ip) => TargetAddress::Ip(*ip),
                                TargetAddress::Domain(_) => TargetAddress::Ip("192.0.2.1".parse()?),
                            },
                            port: target.port,
                        }
                        .encode()?,
                    );
                    send(&mut io, FrameType::OpenOk, frame.stream_id, payload).await?;
                }
                FrameType::TcpData | FrameType::UdpDatagram => {
                    let length = frame.payload.len();
                    send(&mut io, frame.kind, frame.stream_id, frame.payload).await?;
                    if length > 0 {
                        for id in [frame.stream_id, 0] {
                            send(
                                &mut io,
                                FrameType::WindowUpdate,
                                id,
                                (length as u32).to_be_bytes().to_vec(),
                            )
                            .await?;
                        }
                    }
                }
                FrameType::TcpFin => {
                    send(&mut io, FrameType::TcpFin, frame.stream_id, vec![]).await?
                }
                FrameType::Ping => send(&mut io, FrameType::Pong, 0, frame.payload).await?,
                FrameType::WindowUpdate | FrameType::StreamReset => (),
                _ => anyhow::bail!("시험 피어가 예상하지 않은 프레임: {:?}", frame.kind),
            }
        }
    }

    fn fixture(
        executable: &Path,
        name: &str,
        mode: &str,
        result: &Path,
        output: &Path,
    ) -> Result<Child> {
        let log = File::create(output)?;
        Ok(Command::new(executable)
            .args(["--ignored", "--exact", name, "--nocapture"])
            .env("MTP_SPLITTER_RUNTIME_FIXTURE", mode)
            .env("MTP_SPLITTER_RUNTIME_RESULT", result)
            .env(
                "MTP_SPLITTER_LOG",
                "info,mtp_splitter::relay=debug,mtp_splitter::platform::network=trace",
            )
            .creation_flags(0x08000000)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?)
    }
    async fn wait_child(child: &mut Child, seconds: u64) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            if let Some(status) = child.try_wait()? {
                ensure!(status.success(), "시험 자식이 실패했습니다: {status}");
                return Ok(());
            }
            ensure!(Instant::now() < deadline, "시험 자식 종료 시간 초과");
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }

    struct KernelCase {
        api: Arc<DivertApi>,
        sink: Option<Arc<DivertHandle>>,
        sink_thread: Option<thread::JoinHandle<()>>,
        packets: Arc<Mutex<Vec<SocketAddr>>>,
        _ipv6_tcp_canary: std::net::TcpListener,
        _ipv6_udp_canary: UdpSocket,
        parent: Option<Child>,
        target: Option<Child>,
        watchdog: Option<(u32, HANDLE)>,
        _workspace_lock: File,
        label: String,
        // DLL 라이브러리와 프로세스 핸들을 먼저 해제한 뒤 마지막에 시험 폴더를 지운다.
        dir: Directory,
    }
    impl KernelCase {
        fn new(label: &str) -> Result<Self> {
            let source = workspace()?;
            let lock = source.lock()?;
            drop(guard_lock::root_lock(&source)?);
            let dir = Directory::new();
            for name in [
                "bin/WinDivert.dll",
                "bin/WinDivert64.sys",
                "bin/watchdog.exe",
            ] {
                fs::copy(source.resolve(name)?, dir.paths.resolve(name)?)?;
            }
            for name in ["parent.exe", "target.exe"] {
                fs::copy(std::env::current_exe()?, dir.paths.resolve(name)?)?;
            }
            let api = DivertApi::load(&dir.paths)?;
            let ipv6_tcp_canary = std::net::TcpListener::bind("[::1]:18082")?;
            let ipv6_udp_canary = UdpSocket::bind("[::1]:19002")?;
            // 문서용 IPv4와 Fake-IP 원본 패킷은 시험 오류가 나도 외부로 보내지 않는다.
            let sink = Arc::new(api.open("outbound and ((ip.DstAddr == 192.0.2.1) or (ip.DstAddr >= 198.18.0.0 and ip.DstAddr <= 198.19.255.255) or (ipv6.DstAddr == ::1 and ((tcp and tcp.DstPort == 18082) or (udp and udp.DstPort == 19002))))", 0, -2000, 0)?);
            let packets = Arc::new(Mutex::new(Vec::new()));
            let handle = Arc::clone(&sink);
            let observed = Arc::clone(&packets);
            let sink_thread = thread::spawn(move || {
                let mut buffer = vec![0; 65575];
                while let Ok((length, _)) = handle.receive(&mut buffer) {
                    if let Ok(meta) = packet::parse(&buffer[..length]) {
                        observed.lock().unwrap().push(meta.source);
                    }
                }
            });
            Ok(Self {
                dir,
                api,
                sink: Some(sink),
                sink_thread: Some(sink_thread),
                packets,
                _ipv6_tcp_canary: ipv6_tcp_canary,
                _ipv6_udp_canary: ipv6_udp_canary,
                parent: None,
                target: None,
                watchdog: None,
                _workspace_lock: lock,
                label: label.into(),
            })
        }
        fn configure(&self, server: &mtp_splitter::config::ServerConfig) -> Result<()> {
            for (relative, bytes) in [
                ("config/server.json", serde_json::to_vec_pretty(server)?),
                (
                    "config/security.json",
                    serde_json::to_vec_pretty(&self.dir.security())?,
                ),
                (
                    "config/rules.json",
                    serde_json::to_vec_pretty(&vec![ProcessRule {
                        exe_name: Some("target.exe".into()),
                        path_glob: None,
                        sha256: None,
                        include_children: true,
                    }])?,
                ),
            ] {
                fs::write(self.dir.paths.resolve(relative)?, bytes)?;
            }
            Ok(())
        }
        fn find_watchdog(&mut self) -> Result<bool> {
            for entry in fs::read_dir(self.dir.paths.resolve("runtime")?)? {
                let name = entry?.file_name().to_string_lossy().into_owned();
                if let Some(pid) = name
                    .strip_prefix("watchdog-")
                    .and_then(|s| s.strip_suffix(".token"))
                {
                    let pid: u32 = pid.parse()?;
                    let identity = mtp_splitter::platform::processes::identity(pid, 0)?;
                    ensure!(
                        identity.image.canonicalize()?
                            == self.dir.paths.resolve("bin/watchdog.exe")?.canonicalize()?,
                        "시험 watchdog 이미지가 다릅니다"
                    );
                    let handle = unsafe { OpenProcess(0x00100000, 0, pid) };
                    ensure!(!handle.is_null(), "시험 watchdog 대기 핸들 실패");
                    self.watchdog = Some((pid, handle));
                    return Ok(true);
                }
            }
            Ok(false)
        }
        async fn wait_ready(&mut self) -> Result<()> {
            let deadline = Instant::now() + Duration::from_secs(40);
            loop {
                if self.watchdog.is_none() {
                    self.find_watchdog()?;
                }
                if self.watchdog.is_some()
                    && SharedState::open(&self.dir.paths, false)
                        .and_then(|s| s.snapshot())
                        .is_ok_and(|s| s.state == TunnelState::Connected)
                {
                    return Ok(());
                }
                if let Some(parent) = &mut self.parent {
                    ensure!(
                        parent.try_wait()?.is_none(),
                        "메인 시험 피어가 준비 전에 종료됐습니다"
                    );
                }
                ensure!(Instant::now() < deadline, "실행부 준비 시간 초과");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        fn release(&self) -> Result<()> {
            if let Some((pid, handle)) = self.watchdog
                && unsafe { WaitForSingleObject(handle, 0) } != WAIT_OBJECT_0
            {
                watchdog::request_release(&self.dir.paths, pid)?;
                ensure!(
                    unsafe { WaitForSingleObject(handle, 12000) } == WAIT_OBJECT_0,
                    "시험 watchdog 해제 시간 초과"
                );
            }
            Ok(())
        }
    }
    impl Drop for KernelCase {
        fn drop(&mut self) {
            // 이 시험이 직접 생성한 자식만 종료하고 운영 watchdog에는 접근하지 않는다.
            for child in [&mut self.target, &mut self.parent].into_iter().flatten() {
                if child.try_wait().ok().flatten().is_none() {
                    let _ = child.kill();
                }
                let _ = child.wait();
            }
            if self.watchdog.is_none() {
                let _ = self.find_watchdog();
            }
            if let Err(error) = self.release() {
                eprintln!("시험 감시 해제 실패: {error:#}");
            }
            if let Some((_, handle)) = self.watchdog.take() {
                unsafe {
                    CloseHandle(handle);
                }
            }
            if let Some(sink) = self.sink.take() {
                let _ = sink.shutdown();
                drop(sink);
            }
            if let Some(worker) = self.sink_thread.take() {
                let _ = worker.join();
            }
            // 실패한 실행도 원인을 조사할 수 있게 토큰·키를 제외한 시험 기록을 남긴다.
            if let Ok(output) = workspace().and_then(|paths| paths.resolve("runtime/verification"))
            {
                for (source, target) in [
                    ("logs/parent-test.log", "runtime-parent-test.log"),
                    ("logs/target-test.log", "runtime-target-test.log"),
                    ("logs/blocked-test.log", "runtime-blocked-test.log"),
                    ("logs/tunnel.log", "runtime-tunnel.log"),
                    ("logs/watchdog.log", "runtime-watchdog.log"),
                    ("runtime/target-result.json", "runtime-target-result.json"),
                    ("runtime/blocked-result.json", "runtime-blocked-result.json"),
                    (
                        "runtime/disconnected-result.json",
                        "runtime-disconnected-result.json",
                    ),
                    (
                        "logs/disconnected-test.log",
                        "runtime-disconnected-test.log",
                    ),
                ] {
                    if let Ok(source) = self.dir.paths.resolve(source)
                        && source.is_file()
                    {
                        let _ = fs::copy(
                            source,
                            output.join(format!(
                                "{}-{}",
                                self.label,
                                target.strip_prefix("runtime-").unwrap_or(target)
                            )),
                        );
                    }
                }
            }
            if let Err(error) = driver_service::cleanup_idle(&self.dir.paths, &self.api) {
                eprintln!("시험 드라이버 정리 실패: {error:#}");
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "관리자 권한·실제 드라이버·release watchdog을 사용하는 투명 실행 및 충돌 시험"]
    async fn kernel_runtime_routes_dns_tcp_udp_and_watchdog_blocks_new_sockets_after_main_crash()
    -> Result<()> {
        let mut case = KernelCase::new("runtime")?;
        let (server, peer) = support::start_gateway_peer(Settings::default(), |io| async move {
            let result = echo_gateway(io).await;
            if let Err(error) = &result {
                eprintln!("시험 게이트웨이 종료: {error:#}");
            }
            result
        })
        .await;
        case.configure(&server)?;
        case.parent = Some(fixture(
            &case.dir.paths.resolve("parent.exe")?,
            "windows::runtime_parent_fixture",
            "retain",
            &case.dir.paths.resolve("runtime/stop")?,
            &case.dir.paths.resolve("logs/parent-test.log")?,
        )?);
        case.wait_ready().await?;
        let pid = case.watchdog.context("감시 PID 누락")?.0;
        let result_path = case.dir.paths.resolve("runtime/target-result.json")?;
        case.target = Some(fixture(
            &case.dir.paths.resolve("target.exe")?,
            "windows::runtime_target_fixture",
            "roundtrip",
            &result_path,
            &case.dir.paths.resolve("logs/target-test.log")?,
        )?);
        wait_child(case.target.as_mut().unwrap(), 25).await?;
        println!(
            "UDP/TCP DNS 합성·Fake-IP 도메인 전달·IPv4/IPv6 UDP 경계·TCP 64KiB 왕복 및 half-close 성공"
        );
        ensure!(
            case.packets.lock().unwrap().is_empty(),
            "대상 원본 패킷이 최하위 차단에 도달했습니다"
        );
        peer.abort();
        let _ = peer.await;
        let deadline = Instant::now() + Duration::from_secs(5);
        while SharedState::open(&case.dir.paths, false)?.snapshot()?.state == TunnelState::Connected
        {
            ensure!(
                Instant::now() < deadline,
                "게이트웨이 단절 뒤 연결 상태가 내려가지 않았습니다"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        case.target = Some(fixture(
            &case.dir.paths.resolve("target.exe")?,
            "windows::runtime_target_fixture",
            "blocked",
            &case.dir.paths.resolve("runtime/disconnected-result.json")?,
            &case.dir.paths.resolve("logs/disconnected-test.log")?,
        )?);
        wait_child(case.target.as_mut().unwrap(), 15).await?;
        ensure!(
            case.packets.lock().unwrap().is_empty(),
            "게이트웨이 단절 뒤 대상 원본이 통과했습니다"
        );
        println!(
            "운영 실행 중 게이트웨이 단절 감지·IPv4/IPv6 신규 TCP 거부·UDP 차단, 직접 통과 0 확인"
        );
        let parent = case.parent.as_mut().unwrap();
        parent.kill()?;
        parent.wait()?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        ensure!(
            unsafe { WaitForSingleObject(case.watchdog.unwrap().1, 0) } != WAIT_OBJECT_0,
            "메인 충돌 후 watchdog이 종료됐습니다"
        );
        case.target = Some(fixture(
            &case.dir.paths.resolve("target.exe")?,
            "windows::runtime_target_fixture",
            "blocked",
            &case.dir.paths.resolve("runtime/blocked-result.json")?,
            &case.dir.paths.resolve("logs/blocked-test.log")?,
        )?);
        wait_child(case.target.as_mut().unwrap(), 15).await?;
        ensure!(
            case.packets.lock().unwrap().is_empty(),
            "메인 충돌 후 새 대상 소켓의 원본이 통과했습니다"
        );
        ensure!(
            guard_lock::root_lock(&case.dir.paths).is_err(),
            "남은 watchdog의 수명 잠금이 풀렸습니다"
        );
        println!(
            "메인 강제 종료 뒤 watchdog PID={pid} 유지, 신규 TCP 거부·UDP 차단, 직접 통과 0 확인"
        );
        let roundtrip: serde_json::Value = serde_json::from_slice(&fs::read(&result_path)?)?;
        let reused: SocketAddr = roundtrip["udp_source"]
            .as_str()
            .context("대상 UDP 포트 기록 누락")?
            .parse()?;
        let untracked = UdpSocket::bind(reused).context("종료한 대상의 UDP 포트 재사용 실패")?;
        untracked.send_to(b"untracked-control", "192.0.2.1:19001")?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while case.packets.lock().unwrap().is_empty() {
            ensure!(
                Instant::now() < deadline,
                "비대상 대조 패킷이 일반 통과하지 않았습니다"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        ensure!(
            case.packets
                .lock()
                .unwrap()
                .iter()
                .all(|source| source.port() == untracked.local_addr().unwrap().port()),
            "비대상 대조 패킷 외의 원본이 통과했습니다"
        );
        case.release()?;
        ensure!(
            !case.dir.paths.resolve("runtime/nat_session.bin")?.exists(),
            "충돌 후 공유 NAT 파일이 정리되지 않았습니다"
        );
        drop(guard_lock::root_lock(&case.dir.paths)?);
        println!(
            "종료한 대상의 UDP 포트를 재사용한 비대상 앱의 통과·명시적 해제·공유 NAT 정리 성공"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "관리자 권한에서 기본 정지·명시적 종료 해제·실행 중 해제의 수명을 검증"]
    async fn kernel_runtime_distinguishes_default_stop_from_explicit_release() -> Result<()> {
        for mode in ["signal-release", "external-release", "signal-retain"] {
            let mut case = KernelCase::new(&format!("runtime-{mode}"))?;
            let (server, peer) =
                support::start_gateway_peer(Settings::default(), echo_gateway).await;
            case.configure(&server)?;
            let stop = case.dir.paths.resolve("runtime/stop")?;
            case.parent = Some(fixture(
                &case.dir.paths.resolve("parent.exe")?,
                "windows::runtime_parent_fixture",
                if mode == "signal-release" {
                    "release"
                } else {
                    "retain"
                },
                &stop,
                &case.dir.paths.resolve("logs/parent-test.log")?,
            )?);
            case.wait_ready().await?;
            let (pid, handle) = case.watchdog.context("감시 핸들 누락")?;
            if mode == "external-release" {
                watchdog::request_release(&case.dir.paths, pid)?;
            } else {
                fs::write(&stop, b"stop")?;
            }
            wait_child(case.parent.as_mut().unwrap(), 15).await?;
            if mode == "signal-retain" {
                ensure!(
                    unsafe { WaitForSingleObject(handle, 0) } != WAIT_OBJECT_0,
                    "기본 정지가 차단을 해제했습니다"
                );
                ensure!(
                    guard_lock::root_lock(&case.dir.paths).is_err(),
                    "기본 정지 뒤 수명 잠금이 없습니다"
                );
                case.release()?;
            } else {
                ensure!(
                    unsafe { WaitForSingleObject(handle, 0) } == WAIT_OBJECT_0,
                    "명시적 해제 뒤 감시가 종료되지 않았습니다"
                );
            }
            ensure!(
                !case.dir.paths.resolve("runtime/nat_session.bin")?.exists(),
                "해제 뒤 공유 NAT 파일이 남았습니다"
            );
            for suffix in ["token", "release", "stop-main"] {
                ensure!(
                    !case
                        .dir
                        .paths
                        .resolve(format!("runtime/watchdog-{pid}.{suffix}"))?
                        .exists(),
                    "해제 상태 파일이 남았습니다: {suffix}"
                );
            }
            drop(guard_lock::root_lock(&case.dir.paths)?);
            println!("{mode}: 종료 정책·감시 수명·앱 내부 상태 정리 성공");
            peer.abort();
            let _ = peer.await;
        }
        Ok(())
    }

    #[test]
    #[ignore = "부모 통합 시험에서 별도 실행 이미지로만 호출하는 메인 실행 피어"]
    fn runtime_parent_fixture() -> Result<()> {
        let paths = Arc::new(AppPaths::discover()?);
        mtp_splitter::logging::install(&paths)?;
        let stop = PathBuf::from(std::env::var("MTP_SPLITTER_RUNTIME_RESULT")?);
        let release = std::env::var("MTP_SPLITTER_RUNTIME_FIXTURE")? == "release";
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?
            .block_on(runtime::run_until(
                paths,
                RunOptions {
                    tcp_port: 0,
                    udp_port: 0,
                    release_on_exit: release,
                },
                async move {
                    while !stop.exists() {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Ok(())
                },
            ))?;
        Ok(())
    }

    #[test]
    #[ignore = "부모 통합 시험에서 규칙에 일치하는 별도 이미지로만 호출하는 대상 앱"]
    fn runtime_target_fixture() -> Result<()> {
        let result = PathBuf::from(std::env::var("MTP_SPLITTER_RUNTIME_RESULT")?);
        let mode = std::env::var("MTP_SPLITTER_RUNTIME_FIXTURE")?;
        if mode == "blocked" {
            let udp = UdpSocket::bind("0.0.0.0:0")?;
            udp.send_to(b"must-not-pass", "192.0.2.1:19001")?;
            let start = Instant::now();
            let error =
                TcpStream::connect_timeout(&"192.0.2.1:18081".parse()?, Duration::from_secs(7))
                    .err()
                    .context("차단할 TCP가 연결됐습니다")?;
            ensure!(
                [Some(10061), Some(10054)].contains(&error.raw_os_error()),
                "TCP가 RST 거부 대신 다른 오류로 끝났습니다: {error}"
            );
            let udp6 = UdpSocket::bind("[::1]:0")?;
            udp6.send_to(b"ipv6-must-not-pass", "[::1]:19002")?;
            let error6 =
                TcpStream::connect_timeout(&"[::1]:18082".parse()?, Duration::from_secs(7))
                    .err()
                    .context("차단할 IPv6 TCP가 연결됐습니다")?;
            ensure!(
                [Some(10061), Some(10054)].contains(&error6.raw_os_error()),
                "IPv6 TCP가 RST 거부 대신 다른 오류로 끝났습니다: {error6}"
            );
            fs::write(
                result,
                format!(
                    "{{\"tcp_error\":{},\"elapsed_ms\":{},\"tcp6_error\":{}}}",
                    error.raw_os_error().unwrap(),
                    start.elapsed().as_millis(),
                    error6.raw_os_error().unwrap()
                ),
            )?;
            return Ok(());
        }
        ensure!(mode == "roundtrip", "시험 모드 오류");
        let dns = UdpSocket::bind("0.0.0.0:0")?;
        dns.set_read_timeout(Some(Duration::from_secs(8)))?;
        dns.connect("192.0.2.1:53")?;
        let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        fake_dns::encode_name("kernel.example", &mut query)?;
        query.extend_from_slice(&[0, 1, 0, 1]);
        dns.send(&query)?;
        let mut answer = [0; 2048];
        let length = dns.recv(&mut answer).context("커널 DNS 응답 수신 실패")?;
        ensure!(
            length >= 4 && answer[..2] == [0x12, 0x34],
            "DNS 트랜잭션이 다릅니다"
        );
        let fake = std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&answer[length - 4..length])?);
        ensure!(
            fake_dns::is_fake(fake),
            "합성 DNS가 Fake-IP를 반환하지 않았습니다"
        );
        let mut tcp_dns =
            TcpStream::connect_timeout(&"192.0.2.1:53".parse()?, Duration::from_secs(8))?;
        tcp_dns.set_read_timeout(Some(Duration::from_secs(8)))?;
        tcp_dns.write_all(&(query.len() as u16).to_be_bytes())?;
        tcp_dns.write_all(&query)?;
        let mut prefix = [0; 2];
        tcp_dns.read_exact(&mut prefix)?;
        let mut tcp_answer = vec![0; usize::from(u16::from_be_bytes(prefix))];
        tcp_dns.read_exact(&mut tcp_answer)?;
        ensure!(
            tcp_answer == answer[..length],
            "TCP와 UDP DNS 응답이 다릅니다"
        );
        let udp = UdpSocket::bind("0.0.0.0:0")?;
        udp.set_read_timeout(Some(Duration::from_secs(8)))?;
        udp.connect((fake, 19000))?;
        for bytes in [vec![], b"udp-through-kernel".to_vec(), vec![0x5a; 1397]] {
            udp.send(&bytes)?;
            let mut buffer = [0; 2048];
            let length = udp.recv(&mut buffer).context("커널 UDP 응답 수신 실패")?;
            ensure!(buffer[..length] == bytes, "UDP 데이터그램이 다릅니다");
        }
        let mut tcp =
            TcpStream::connect_timeout(&"192.0.2.1:18080".parse()?, Duration::from_secs(8))?;
        tcp.set_read_timeout(Some(Duration::from_secs(8)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(8)))?;
        let bytes: Vec<_> = (0..65536).map(|index| index as u8).collect();
        tcp.write_all(&bytes)?;
        tcp.shutdown(Shutdown::Write)?;
        let mut echoed = Vec::new();
        tcp.read_to_end(&mut echoed)?;
        ensure!(echoed == bytes, "TCP 64KiB 왕복이 다릅니다");
        let udp6 = UdpSocket::bind("[::1]:0")?;
        udp6.set_read_timeout(Some(Duration::from_secs(8)))?;
        udp6.connect("[::1]:19002")?;
        for bytes in [vec![], b"ipv6-through-kernel".to_vec(), vec![0x6a; 1397]] {
            udp6.send(&bytes)?;
            let mut buffer = [0; 2048];
            let length = udp6.recv(&mut buffer).context("IPv6 커널 UDP 응답 실패")?;
            ensure!(buffer[..length] == bytes, "IPv6 UDP 데이터그램이 다릅니다");
        }
        let mut tcp6 = TcpStream::connect_timeout(&"[::1]:18082".parse()?, Duration::from_secs(8))
            .context("IPv6 커널 TCP 연결 실패")?;
        tcp6.set_read_timeout(Some(Duration::from_secs(8)))?;
        tcp6.set_write_timeout(Some(Duration::from_secs(8)))?;
        tcp6.write_all(&bytes)?;
        tcp6.shutdown(Shutdown::Write)?;
        let mut echoed6 = Vec::new();
        tcp6.read_to_end(&mut echoed6)
            .context("IPv6 커널 TCP 수신 실패")?;
        ensure!(echoed6 == bytes, "IPv6 TCP 64KiB 왕복이 다릅니다");
        fs::write(
            result,
            format!(
                "{{\"fake_ip\":\"{fake}\",\"tcp_bytes\":{},\"udp_source\":\"{}\"}}",
                bytes.len(),
                udp.local_addr()?
            ),
        )?;
        Ok(())
    }
}
