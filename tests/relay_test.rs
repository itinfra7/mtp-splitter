//! 실제 loopback 소켓과 상호 인증 터널을 통과하는 TCP·UDP·DNS 릴레이를 검증한다.
//! WinDivert 커널 재주입 검증과는 구분한다.

mod support;
use anyhow::{Result, ensure};
use mtp_splitter::{
    fake_dns::{self, DnsError, FakeIpCache},
    gateway::{GatewayClient, Limits},
    nat_engine::{FlowKey, NatSession, NatSessionTable, TunnelStatus},
    packet::Protocol,
    protocol::{ErrorCode, ErrorMessage, Frame, FrameType, Settings, Target, TargetAddress},
    relay::{self, DnsService, GatewaySlot, RelayContext, RelayLimits},
    transport,
};
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use support::{Directory, TestGatewayIo, start_gateway_peer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{oneshot, watch},
};

async fn next_data(io: &mut TestGatewayIo) -> Result<Frame> {
    loop {
        let frame = transport::read_frame(io).await?;
        match frame.kind {
            FrameType::WindowUpdate => (),
            FrameType::Ping => {
                transport::write_frame(
                    io,
                    &Frame {
                        kind: FrameType::Pong,
                        ..frame
                    },
                )
                .await?
            }
            _ => return Ok(frame),
        }
    }
}
async fn send(io: &mut TestGatewayIo, kind: FrameType, id: u32, payload: Vec<u8>) -> Result<()> {
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
async fn credit(io: &mut TestGatewayIo, id: u32, length: usize) -> Result<()> {
    if length != 0 {
        send(
            io,
            FrameType::WindowUpdate,
            id,
            (length as u32).to_be_bytes().to_vec(),
        )
        .await?;
        send(
            io,
            FrameType::WindowUpdate,
            0,
            (length as u32).to_be_bytes().to_vec(),
        )
        .await?;
    }
    Ok(())
}
fn endpoint(address: SocketAddr) -> Target {
    Target {
        address: TargetAddress::Ip(address.ip()),
        port: address.port(),
    }
}
async fn open_ok(
    io: &mut TestGatewayIo,
    id: u32,
    local: SocketAddr,
    peer: SocketAddr,
) -> Result<()> {
    let mut payload = endpoint(local).encode()?;
    payload.extend_from_slice(&endpoint(peer).encode()?);
    send(io, FrameType::OpenOk, id, payload).await
}
async fn connect(dir: &Directory, server: &mtp_splitter::config::ServerConfig) -> GatewayClient {
    GatewayClient::connect(
        server,
        &dir.security(),
        &dir.paths,
        Arc::new(TunnelStatus::default()),
        Limits::default(),
    )
    .await
    .unwrap()
}
fn query(name: &str, qtype: u16) -> Vec<u8> {
    let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    fake_dns::encode_name(name, &mut query).unwrap();
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&[0, 1]);
    query
}
fn dns(
    dir: &Directory,
    slot: Arc<GatewaySlot>,
    size: usize,
) -> (Arc<DnsService>, Arc<Mutex<FakeIpCache>>) {
    let cache = Arc::new(Mutex::new(FakeIpCache::new(
        NonZeroUsize::new(size).unwrap(),
    )));
    (
        Arc::new(DnsService::new(
            Arc::clone(&cache),
            Arc::new(dir.paths.clone()),
            slot,
        )),
        cache,
    )
}

#[tokio::test]
async fn actual_tcp_relay_preserves_half_close_through_authenticated_gateway() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let dir = Directory::new();
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = echo_listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = echo_listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            socket.read_to_end(&mut bytes).await.unwrap();
            socket.write_all(b"ok:").await.unwrap();
            socket.write_all(&bytes).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let (done, wait) = oneshot::channel();
        let (server, peer) =
            start_gateway_peer(Settings::default(), move |mut secured| async move {
                let open = next_data(&mut secured).await?;
                ensure!(open.kind == FrameType::OpenTcp, "TCP OPEN이 아닙니다");
                ensure!(
                    Target::decode(&open.payload)?.0 == endpoint(target),
                    "TCP 목적지가 다릅니다"
                );
                let mut remote = TcpStream::connect(target).await?;
                open_ok(
                    &mut secured,
                    open.stream_id,
                    remote.local_addr()?,
                    remote.peer_addr()?,
                )
                .await?;
                loop {
                    let frame = next_data(&mut secured).await?;
                    ensure!(
                        frame.stream_id == open.stream_id,
                        "TCP 스트림 ID가 다릅니다"
                    );
                    match frame.kind {
                        FrameType::TcpData => {
                            remote.write_all(&frame.payload).await?;
                            credit(&mut secured, frame.stream_id, frame.payload.len()).await?;
                        }
                        FrameType::TcpFin => {
                            remote.shutdown().await?;
                            break;
                        }
                        _ => anyhow::bail!("예상하지 않은 TCP 프레임입니다"),
                    }
                }
                let mut buffer = [0; 16384];
                loop {
                    let length = remote.read(&mut buffer).await?;
                    if length == 0 {
                        break;
                    }
                    send(
                        &mut secured,
                        FrameType::TcpData,
                        open.stream_id,
                        buffer[..length].to_vec(),
                    )
                    .await?;
                }
                send(&mut secured, FrameType::TcpFin, open.stream_id, Vec::new()).await?;
                let _ = wait.await;
                Ok(())
            })
            .await;
        let gateway = connect(&dir, &server).await;
        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_address = local_listener.local_addr().unwrap();
        let relay_gateway = gateway.clone();
        let forwarding = tokio::spawn(async move {
            let (socket, _) = local_listener.accept().await.unwrap();
            relay::forward_tcp(socket, relay_gateway, endpoint(target)).await
        });
        let mut app = TcpStream::connect(local_address).await.unwrap();
        let payload: Vec<_> = (0..100000).map(|index| index as u8).collect();
        app.write_all(&payload).await.unwrap();
        app.shutdown().await.unwrap();
        let mut response = Vec::new();
        app.read_to_end(&mut response).await.unwrap();
        assert_eq!(&response[..3], b"ok:");
        assert_eq!(&response[3..], payload);
        forwarding.await.unwrap().unwrap();
        echo.await.unwrap();
        done.send(()).unwrap();
        peer.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

async fn bind_alias(nat: &NatSessionTable, target: SocketAddr) -> (NatSession, UdpSocket) {
    for port in 40000..40100 {
        let session = nat
            .register(
                FlowKey {
                    protocol: Protocol::Udp,
                    client: format!("10.0.0.2:{port}").parse().unwrap(),
                    target,
                },
                100,
                0,
            )
            .unwrap();
        if let Ok(socket) = UdpSocket::bind(session.alias).await {
            return (session, socket);
        }
    }
    panic!("테스트용 loopback 별칭 포트를 확보하지 못했습니다");
}

#[tokio::test]
async fn actual_udp_relay_sends_domain_remote_and_preserves_datagrams_and_idle_cleanup() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let dir = Directory::new();
        let echo_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = echo_socket.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut buffer = vec![0; 65536];
            for _ in 0..3 {
                let (length, peer) = echo_socket.recv_from(&mut buffer).await.unwrap();
                assert_eq!(
                    echo_socket.send_to(&buffer[..length], peer).await.unwrap(),
                    length
                );
            }
        });
        let (done, wait) = oneshot::channel();
        let (retired, retirement) = oneshot::channel();
        let (server, peer) =
            start_gateway_peer(Settings::default(), move |mut secured| async move {
                let open = next_data(&mut secured).await?;
                ensure!(open.kind == FrameType::OpenUdp, "UDP OPEN이 아닙니다");
                let requested = Target::decode(&open.payload)?.0;
                ensure!(
                    requested.address == TargetAddress::Domain("remote.example".into())
                        && requested.port == target.port(),
                    "Fake-IP 대신 원격 도메인이 전달돼야 합니다"
                );
                let remote = UdpSocket::bind("127.0.0.1:0").await?;
                remote.connect(target).await?;
                open_ok(&mut secured, open.stream_id, remote.local_addr()?, target).await?;
                let mut buffer = vec![0; 65536];
                for _ in 0..3 {
                    let frame = next_data(&mut secured).await?;
                    ensure!(
                        frame.kind == FrameType::UdpDatagram && frame.stream_id == open.stream_id,
                        "UDP association ID가 다릅니다"
                    );
                    ensure!(
                        remote.send(&frame.payload).await? == frame.payload.len(),
                        "UDP 송신 길이가 다릅니다"
                    );
                    credit(&mut secured, frame.stream_id, frame.payload.len()).await?;
                    let length = remote.recv(&mut buffer).await?;
                    send(
                        &mut secured,
                        FrameType::UdpDatagram,
                        frame.stream_id,
                        buffer[..length].to_vec(),
                    )
                    .await?;
                }
                let reset = next_data(&mut secured).await?;
                ensure!(
                    reset.kind == FrameType::StreamReset && reset.stream_id == open.stream_id,
                    "유휴 association이 해제되지 않았습니다"
                );
                let _ = retired.send(());
                let _ = wait.await;
                Ok(())
            })
            .await;
        let gateway = connect(&dir, &server).await;
        let slot = Arc::new(GatewaySlot::default());
        slot.install(gateway.clone()).unwrap();
        let (dns, cache) = dns(&dir, Arc::clone(&slot), 1);
        let fake = cache.lock().unwrap().allocate("remote.example", 0).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = socket.local_addr().unwrap();
        let nat = Arc::new(NatSessionTable::new(128, 13080, local.port()));
        let (_, app) = bind_alias(&nat, SocketAddr::new(IpAddr::V4(fake), target.port())).await;
        let context = Arc::new(
            RelayContext::new(
                nat,
                dns,
                slot,
                RelayLimits {
                    udp_idle: Duration::from_secs(1),
                    ..RelayLimits::default()
                },
            )
            .unwrap(),
        );
        let (stopping, stopped) = watch::channel(false);
        let forwarding = tokio::spawn(relay::serve_udp(socket, context, stopped));
        app.connect(local).await.unwrap();
        let mut buffer = vec![0; 65536];
        for payload in [Vec::new(), b"hello".to_vec(), vec![42; 60000]] {
            assert_eq!(app.send(&payload).await.unwrap(), payload.len());
            let length = app.recv(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], payload);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(
            cache.lock().unwrap().allocate("other.example", now),
            Err(DnsError::Capacity)
        );
        retirement.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if cache.lock().unwrap().allocate("other.example", now).is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        stopping.send(true).unwrap();
        forwarding.await.unwrap().unwrap();
        echo.await.unwrap();
        done.send(()).unwrap();
        peer.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn udp_dns_is_synthesized_and_persisted_without_gateway_connection() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let dir = Directory::new();
        let slot = Arc::new(GatewaySlot::default());
        let (dns, cache) = dns(&dir, Arc::clone(&slot), 8);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = socket.local_addr().unwrap();
        let nat = Arc::new(NatSessionTable::new(128, 13080, local.port()));
        let (_, app) = bind_alias(&nat, "8.8.8.8:53".parse().unwrap()).await;
        let context = Arc::new(RelayContext::new(nat, dns, slot, RelayLimits::default()).unwrap());
        let (stopping, stopped) = watch::channel(false);
        let task = tokio::spawn(relay::serve_udp(socket, context, stopped));
        let request = query("example.com", 1);
        app.send_to(&request, local).await.unwrap();
        let mut buffer = [0; 512];
        let (length, _) = app.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[length - 4..length], &[198, 18, 0, 1]);
        assert_eq!(cache.lock().unwrap().len(), 1);
        let mut stored = FakeIpCache::load(&dir.paths, NonZeroUsize::new(8).unwrap()).unwrap();
        assert_eq!(
            stored.domain("198.18.0.1".parse().unwrap()).as_deref(),
            Some("example.com")
        );
        stopping.send(true).unwrap();
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tcp_dns_handles_pipelined_questions_and_preserves_question_case() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let dir = Directory::new();
        let (dns, _) = dns(&dir, Arc::new(GatewaySlot::default()), 8);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            dns.serve_tcp(socket, Duration::from_secs(2)).await
        });
        let mut app = TcpStream::connect(local).await.unwrap();
        let mut a = query("example.com", 1);
        a[13] = b'E';
        a[15] = b'A';
        let aaaa = query("example.com", 28);
        for request in [&a, &aaaa] {
            app.write_all(&(request.len() as u16).to_be_bytes())
                .await
                .unwrap();
            app.write_all(request).await.unwrap();
        }
        for expected_answers in [1u8, 0] {
            let length = app.read_u16().await.unwrap();
            let mut response = vec![0; usize::from(length)];
            app.read_exact(&mut response).await.unwrap();
            assert_eq!(response[7], expected_answers);
            if expected_answers == 1 {
                assert_eq!(
                    fake_dns::decode_name(&response, 12).unwrap().0,
                    "ExAmple.com"
                );
            }
        }
        app.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn non_address_dns_query_uses_authenticated_remote_rpc() {
    let dir = Directory::new();
    let (done, wait) = oneshot::channel();
    let request = query("example.com", 16);
    let expected = request.clone();
    let (server, peer) = start_gateway_peer(Settings::default(), move |mut secured| async move {
        let frame = next_data(&mut secured).await?;
        ensure!(
            frame.kind == FrameType::DnsQuery && frame.payload == expected,
            "원격 TXT DNS 요청이 다릅니다"
        );
        let mut response = frame.payload;
        response[2] |= 0x80;
        send(
            &mut secured,
            FrameType::DnsResponse,
            frame.stream_id,
            response,
        )
        .await?;
        let _ = wait.await;
        Ok(())
    })
    .await;
    let gateway = connect(&dir, &server).await;
    let slot = Arc::new(GatewaySlot::default());
    slot.install(gateway).unwrap();
    let (dns, cache) = dns(&dir, slot, 8);
    let response = dns.answer(request).await.unwrap();
    assert_eq!(response[2] & 0x80, 0x80);
    assert!(cache.lock().unwrap().is_empty());
    done.send(()).unwrap();
    peer.await.unwrap().unwrap();
}

#[tokio::test]
async fn refused_gateway_resets_local_tcp_and_never_tries_direct_destination() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let dir = Directory::new();
        let canary = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = canary.local_addr().unwrap();
        let (done, wait) = oneshot::channel();
        let (server, peer) =
            start_gateway_peer(Settings::default(), move |mut secured| async move {
                let open = next_data(&mut secured).await?;
                send(
                    &mut secured,
                    FrameType::OpenError,
                    open.stream_id,
                    ErrorMessage::new(ErrorCode::Refused, "거부 시험").encode()?,
                )
                .await?;
                let _ = wait.await;
                Ok(())
            })
            .await;
        let gateway = connect(&dir, &server).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            relay::forward_tcp(socket, gateway, endpoint(target)).await
        });
        let mut app = TcpStream::connect(local).await.unwrap();
        let write = app.write_all(b"request").await;
        let read = app.read(&mut [0; 1]).await;
        assert!(write.is_err() || read.is_err());
        assert!(relay.await.unwrap().is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(100), canary.accept())
                .await
                .is_err()
        );
        done.send(()).unwrap();
        peer.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unsupported_dns_type_returns_servfail_when_gateway_is_down() {
    let dir = Directory::new();
    let (dns, cache) = dns(&dir, Arc::new(GatewaySlot::default()), 8);
    let response = dns.answer(query("example.com", 16)).await.unwrap();
    assert_eq!(response[3] & 15, 2);
    assert!(cache.lock().unwrap().is_empty());
}
