//! 문서용 목적지로 향하는 전용 소켓만 포착하여 실제 커널 NAT 왕복을 검사한다.
//! 낮은 우선순위의 DROP 핸들이 원본 패킷의 외부 송신을 추가로 차단한다.

use super::{divert::DivertApi, monitor::ProcessMonitor, network::NetworkEngine};
use crate::{
    config::ProcessRule,
    nat_engine::{NatSessionTable, TunnelState, TunnelStatus},
    packet_router::PacketRouter,
    process_tracker::ActiveSocketTable,
};

fn monitored_router(
    api: &Arc<DivertApi>,
    tcp_port: u16,
    udp_port: u16,
    started: Instant,
) -> Result<(Arc<PacketRouter>, ProcessMonitor)> {
    let status = Arc::new(TunnelStatus::default());
    // 이 진단의 전송 대상은 아래 로컬 echo 피어다. 일반 실행의 인증된 게이트웨이 상태를 대신하지 않는다.
    status.set(TunnelState::Connected);
    let router = Arc::new(PacketRouter::new(
        Arc::new(NatSessionTable::new(16, tcp_port, udp_port)),
        Arc::new(ActiveSocketTable::default()),
        status,
        [],
    ));
    let executable = std::env::current_exe()?;
    let name = executable
        .file_name()
        .context("시험 실행 파일 이름이 없습니다")?
        .to_string_lossy()
        .into_owned();
    // 전용 포트 필터 안에서만 자기 소켓을 대상으로 삼아 실제 소유권 수집을 검사한다.
    let rules = vec![ProcessRule {
        exe_name: Some(name),
        path_glob: None,
        sha256: None,
        include_children: false,
    }];
    let monitor = ProcessMonitor::start(api, Arc::clone(&router), rules, [], started)?;
    Ok((router, monitor))
}
use anyhow::{Context, Result, ensure};
use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub fn udp(api: &Arc<DivertApi>) -> Result<()> {
    let origin = UdpSocket::bind("0.0.0.0:0")?;
    origin.connect("192.0.2.1:9")?;
    origin.set_read_timeout(Some(Duration::from_secs(3)))?;
    let local = origin.local_addr()?;
    let echo = UdpSocket::bind("127.0.0.1:0")?;
    echo.set_read_timeout(Some(Duration::from_secs(3)))?;
    let relay = echo.local_addr()?;
    let original_filter = format!(
        "outbound and udp and udp.SrcPort == {} and ip.SrcAddr == {} and ip.DstAddr == 192.0.2.1 and udp.DstPort == 9",
        local.port(),
        local.ip()
    );
    let filter = format!(
        "({original_filter}) or (outbound and udp and ip.SrcAddr == 127.0.0.1 and udp.SrcPort == {} and ip.DstAddr == 127.0.0.2)",
        relay.port()
    );
    let guard = api.open(&original_filter, 0, -2000, 2)?;
    let started = Instant::now();
    let (router, monitor) = monitored_router(api, 0, relay.port(), started)?;
    let engine = NetworkEngine::start(api, router, &filter, started)?;
    let result = (|| -> Result<()> {
        for payload in [&[][..], &b"mtp-splitter-kernel-nat"[..], &[0x5a; 1400][..]] {
            origin.send(payload)?;
            let mut bytes = [0; 2048];
            let (length, alias) = echo
                .recv_from(&mut bytes)
                .context("커널 NAT 패킷이 루프백 릴레이에 도착하지 않았습니다")?;
            ensure!(
                &bytes[..length] == payload && alias.ip().is_loopback(),
                "NAT 송신 내용 또는 별칭이 다릅니다"
            );
            echo.send_to(&bytes[..length], alias)?;
            let length = origin
                .recv(&mut bytes)
                .context("역변환 패킷이 원래 소켓에 도착하지 않았습니다")?;
            ensure!(&bytes[..length] == payload, "NAT 왕복 데이터가 다릅니다");
            engine.healthy()?;
            monitor.healthy()?;
        }
        Ok(())
    })();
    drop(origin);
    drop(echo);
    drop(engine);
    drop(guard);
    result?;
    println!("전용 UDP 소켓의 실제 커널 NAT·루프백 릴레이·원래 목적지 복원 왕복 3건 성공");
    Ok(())
}

pub fn tcp(api: &Arc<DivertApi>) -> Result<()> {
    let route = UdpSocket::bind("0.0.0.0:0")?;
    route.connect("192.0.2.1:9")?;
    let local_ip = route.local_addr()?.ip();
    drop(route);
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.bind(&SocketAddr::new(local_ip, 0).into())?;
    let local = socket
        .local_addr()?
        .as_socket()
        .context("TCP 테스트 소켓 주소가 없습니다")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let relay = listener.local_addr()?;
    let original_filter = format!(
        "outbound and tcp and tcp.SrcPort == {} and ip.SrcAddr == {local_ip} and ip.DstAddr == 192.0.2.1 and tcp.DstPort == 9",
        local.port()
    );
    let filter = format!(
        "({original_filter}) or (outbound and tcp and ip.SrcAddr == 127.0.0.1 and tcp.SrcPort == {} and ip.DstAddr == 127.0.0.2)",
        relay.port()
    );
    let guard = api.open(&original_filter, 0, -2000, 2)?;
    let started = Instant::now();
    let (router, monitor) = monitored_router(api, relay.port(), 0, started)?;
    let engine = NetworkEngine::start(api, router, &filter, started)?;
    let stopping = Arc::new(AtomicBool::new(false));
    let peer_stopping = Arc::clone(&stopping);
    let peer = std::thread::Builder::new()
        .name("mtp-nat-tcp-echo".into())
        .spawn(move || -> Result<()> {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !peer_stopping.load(Ordering::Acquire) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, alias)) => {
                        ensure!(alias.ip().is_loopback(), "TCP 별칭이 루프백이 아닙니다");
                        // Windows에서는 accept 결과가 리스너의 비차단 상태를 물려받는다.
                        stream.set_nonblocking(false)?;
                        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
                        let mut input = stream.try_clone()?;
                        let transferred = std::io::copy(&mut input, &mut stream)
                            .context("TCP 시험 릴레이의 복사 실패")?;
                        tracing::info!(transferred, "TCP 시험 릴레이의 수신 EOF");
                        stream.shutdown(Shutdown::Write)?;
                        return Ok(());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            anyhow::bail!("TCP NAT 릴레이에 연결이 도착하지 않았습니다")
        })?;
    let result = (|| -> Result<()> {
        socket
            .connect_timeout(
                &"192.0.2.1:9".parse::<SocketAddr>()?.into(),
                Duration::from_secs(3),
            )
            .context("원래 TCP 소켓의 NAT 연결 실패")?;
        let mut origin: TcpStream = socket.into();
        origin.set_read_timeout(Some(Duration::from_secs(3)))?;
        origin.set_write_timeout(Some(Duration::from_secs(3)))?;
        let payload: Vec<u8> = (0..131072).map(|index| index as u8).collect();
        origin
            .write_all(&payload)
            .context("원래 TCP 소켓의 송신 실패")?;
        origin.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        if let Err(error) = origin.read_to_end(&mut response) {
            anyhow::bail!(
                "원래 TCP 소켓의 수신 실패, 수신 길이 {}: {error}",
                response.len()
            );
        }
        ensure!(response == payload, "TCP NAT 왕복 데이터가 다릅니다");
        engine.healthy()?;
        monitor.healthy()?;
        Ok(())
    })();
    stopping.store(true, Ordering::Release);
    let peer_result = peer
        .join()
        .map_err(|_| anyhow::anyhow!("TCP NAT 시험 피어가 중단됐습니다"));
    if result.is_err() {
        eprintln!(
            "TCP 시험 계수: 통과={}, 주입={}, 차단={}, 큐 초과={}, 소유권 대기 만료={}, 피어 결과={peer_result:?}",
            engine.counters.passed.load(Ordering::Relaxed),
            engine.counters.injected.load(Ordering::Relaxed),
            engine.counters.dropped.load(Ordering::Relaxed),
            engine.counters.queue_full.load(Ordering::Relaxed),
            engine.counters.ownership_expired.load(Ordering::Relaxed)
        );
        engine.healthy()?;
    }
    drop(engine);
    drop(guard);
    result?;
    peer_result??;
    println!("전용 TCP 소켓의 실제 커널 NAT·128KiB 왕복·양방향 half-close 성공");
    Ok(())
}

/// 전용 시험 소켓으로 연결 단절 시 직접 송신 대신 실패 응답을 주입하는지 검사한다.
pub fn reject_when_down(api: &Arc<DivertApi>) -> Result<()> {
    let udp = UdpSocket::bind("0.0.0.0:0")?;
    udp.connect("192.0.2.1:9")?;
    udp.set_read_timeout(Some(Duration::from_secs(1)))?;
    let local = udp.local_addr()?;
    let tcp = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    tcp.bind(&SocketAddr::new(local.ip(), 0).into())?;
    let tcp_local = tcp
        .local_addr()?
        .as_socket()
        .context("단절 시험의 TCP 소켓 주소가 없습니다")?;
    let filter = format!(
        "outbound and ip.SrcAddr == {} and ip.DstAddr == 192.0.2.1 and ((udp and udp.SrcPort == {} and udp.DstPort == 9) or (tcp and tcp.SrcPort == {} and tcp.DstPort == 9))",
        local.ip(),
        local.port(),
        tcp_local.port()
    );
    let guard = api.open(&filter, 0, -2000, 2)?;
    let started = Instant::now();
    let (router, monitor) = monitored_router(api, 0, 0, started)?;
    router.status.set(TunnelState::Down);
    let engine = NetworkEngine::start(api, Arc::clone(&router), &filter, started)?;
    let result = (|| -> Result<()> {
        let target = "192.0.2.1:9".parse::<SocketAddr>()?;
        let connecting = Instant::now();
        let Err(error) = tcp.connect_timeout(&target.into(), Duration::from_secs(7)) else {
            anyhow::bail!("Down 상태에서 TCP가 연결됐습니다");
        };
        ensure!(
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
            ),
            "TCP가 RST 대신 다른 이유로 실패했습니다: {error}"
        );
        let tcp_injections = engine.counters.injected.load(Ordering::Relaxed);
        ensure!(tcp_injections != 0, "TCP RST가 주입되지 않았습니다");
        println!(
            "TCP 단절 시험: {}ms 뒤 오류 {error}, RST 주입 {tcp_injections}건",
            connecting.elapsed().as_millis()
        );
        udp.send(b"must-not-leave")?;
        let mut buffer = [0; 32];
        ensure!(
            udp.recv(&mut buffer).is_err(),
            "Down 상태에서 UDP 응답을 받았습니다"
        );
        engine.healthy()?;
        monitor.healthy()?;
        ensure!(
            engine.counters.injected.load(Ordering::Relaxed) > tcp_injections,
            "TCP RST·UDP ICMP가 모두 주입되지 않았습니다"
        );
        ensure!(
            engine.counters.passed.load(Ordering::Relaxed) == 0 && router.nat.is_empty(),
            "Down 상태에서 패킷 통과 또는 NAT 세션이 발생했습니다"
        );
        Ok(())
    })();
    drop(tcp);
    drop(udp);
    if let Err(error) = &result {
        eprintln!(
            "단절 시험 실패: {error:#}; 주입={}, 통과={}, 차단={}, 대기 만료={}, TCP 소유권={:?}, 이벤트={}, 미확인={}, 오래된 이벤트={}, 패킷 작업={:?}, 감시 작업={:?}",
            engine.counters.injected.load(Ordering::Relaxed),
            engine.counters.passed.load(Ordering::Relaxed),
            engine.counters.dropped.load(Ordering::Relaxed),
            engine.counters.ownership_expired.load(Ordering::Relaxed),
            router.sockets.owner_identity(
                crate::packet::Protocol::Tcp,
                tcp_local,
                started.elapsed().as_millis() as u64
            ),
            monitor.counters.socket_events.load(Ordering::Relaxed),
            monitor.counters.unresolved_events.load(Ordering::Relaxed),
            monitor.counters.stale_events.load(Ordering::Relaxed),
            engine.healthy(),
            monitor.healthy()
        );
    }
    drop(engine);
    drop(monitor);
    drop(guard);
    result?;
    println!("Down 상태의 TCP RST·UDP ICMP 커널 주입과 직접 통과 없음 확인 성공");
    Ok(())
}
