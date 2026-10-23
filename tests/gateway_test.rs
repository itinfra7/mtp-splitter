//! 인증 이후 다중화 세션의 윈도·취소·half-close·독립 스트림 수명을 검증한다.

use mtp_splitter::{
    gateway::{GatewayClient, GatewayStream, Limits, StreamKind},
    nat_engine::{TunnelState, TunnelStatus},
    protocol::{ErrorCode, ErrorMessage, Frame, FrameType, Settings, Target, TargetAddress},
    transport,
};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

fn target() -> Target {
    Target {
        address: TargetAddress::Ip("203.0.113.9".parse().unwrap()),
        port: 443,
    }
}
fn setup(
    peer: Settings,
    local: Settings,
    limits: Limits,
) -> (GatewayClient, DuplexStream, Arc<TunnelStatus>) {
    let (client_io, peer_io) = tokio::io::duplex(1024 * 1024);
    let status = Arc::new(TunnelStatus::default());
    let client =
        GatewayClient::attach_authenticated(client_io, peer, local, Arc::clone(&status), limits)
            .unwrap();
    (client, peer_io, status)
}
async fn next(peer: &mut DuplexStream) -> Frame {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(3), transport::read_frame(peer))
            .await
            .unwrap()
            .unwrap();
        match frame.kind {
            FrameType::WindowUpdate => (),
            FrameType::Ping => transport::write_frame(
                peer,
                &Frame {
                    kind: FrameType::Pong,
                    ..frame
                },
            )
            .await
            .unwrap(),
            _ => return frame,
        }
    }
}
async fn send(peer: &mut DuplexStream, kind: FrameType, stream_id: u32, payload: Vec<u8>) {
    transport::write_frame(
        peer,
        &Frame {
            kind,
            stream_id,
            payload,
        },
    )
    .await
    .unwrap();
}
async fn opened(
    client: &GatewayClient,
    peer: &mut DuplexStream,
    kind: StreamKind,
) -> Arc<GatewayStream> {
    let opening = async {
        match kind {
            StreamKind::Tcp => client.open_tcp(target()).await,
            StreamKind::Udp => client.open_udp(target()).await,
            StreamKind::Dns => panic!("DNS는 별도 요청을 사용합니다"),
        }
    };
    let answering = async {
        let request = next(peer).await;
        assert_eq!(
            request.kind,
            if kind == StreamKind::Tcp {
                FrameType::OpenTcp
            } else {
                FrameType::OpenUdp
            }
        );
        let mut payload = Target {
            address: TargetAddress::Ip("127.0.0.1".parse().unwrap()),
            port: 30000,
        }
        .encode()
        .unwrap();
        payload.extend_from_slice(&request.payload);
        send(peer, FrameType::OpenOk, request.stream_id, payload).await;
    };
    let (stream, _) = tokio::join!(opening, answering);
    stream.unwrap()
}
fn small_settings() -> Settings {
    Settings {
        connection_credit: 8,
        stream_credit: 4,
        capabilities: 1,
        ..Settings::default()
    }
}

#[tokio::test]
async fn independent_tcp_and_udp_streams_preserve_ids_payload_and_empty_datagrams() {
    let (client, mut peer, _) = setup(Settings::default(), Settings::default(), Limits::default());
    let tcp = opened(&client, &mut peer, StreamKind::Tcp).await;
    let udp = opened(&client, &mut peer, StreamKind::Udp).await;
    assert_eq!(tcp.id(), 1);
    assert_eq!(udp.id(), 3);
    tcp.send_tcp(b"tcp").await.unwrap();
    udp.send_datagram(b"udp").await.unwrap();
    udp.send_datagram(&[]).await.unwrap();
    for expected in [b"tcp".as_slice(), b"udp", b""] {
        let frame = next(&mut peer).await;
        assert_eq!(frame.payload, expected);
        send(&mut peer, frame.kind, frame.stream_id, frame.payload).await;
    }
    assert_eq!(tcp.receive().await.unwrap().unwrap(), b"tcp");
    assert_eq!(udp.receive().await.unwrap().unwrap(), b"udp");
    assert!(udp.receive().await.unwrap().unwrap().is_empty());
    assert_eq!(client.active_streams(), 2);
}

#[tokio::test]
async fn transmit_waits_for_window_and_handles_windows_smaller_than_tcp_chunk() {
    let (client, mut peer, _) = setup(small_settings(), Settings::default(), Limits::default());
    let stream = opened(&client, &mut peer, StreamKind::Tcp).await;
    let sending = {
        let stream = Arc::clone(&stream);
        tokio::spawn(async move { stream.send_tcp(b"abcdefgh").await })
    };
    let first = next(&mut peer).await;
    assert_eq!(first.payload, b"abcd");
    assert!(!sending.is_finished());
    send(
        &mut peer,
        FrameType::WindowUpdate,
        stream.id(),
        4u32.to_be_bytes().to_vec(),
    )
    .await;
    let second = next(&mut peer).await;
    assert_eq!(second.payload, b"efgh");
    sending.await.unwrap().unwrap();
}

#[tokio::test]
async fn receive_releases_stream_and_connection_credit_only_when_consumed() {
    let (client, mut peer, _) = setup(Settings::default(), small_settings(), Limits::default());
    let stream = opened(&client, &mut peer, StreamKind::Tcp).await;
    send(&mut peer, FrameType::TcpData, stream.id(), b"abcd".to_vec()).await;
    assert_eq!(stream.receive().await.unwrap().unwrap(), b"abcd");
    let first = transport::read_frame(&mut peer).await.unwrap();
    let second = transport::read_frame(&mut peer).await.unwrap();
    assert_eq!(first.kind, FrameType::WindowUpdate);
    assert_eq!(first.stream_id, stream.id());
    assert_eq!(first.payload, 4u32.to_be_bytes());
    assert_eq!(second.stream_id, 0);
    assert_eq!(second.payload, first.payload);
    send(&mut peer, FrameType::TcpData, stream.id(), b"efgh".to_vec()).await;
    assert_eq!(stream.receive().await.unwrap().unwrap(), b"efgh");
}

#[tokio::test]
async fn peer_window_violation_closes_tunnel_and_marks_status_down() {
    let (client, mut peer, status) =
        setup(Settings::default(), small_settings(), Limits::default());
    let stream = opened(&client, &mut peer, StreamKind::Tcp).await;
    send(&mut peer, FrameType::TcpData, stream.id(), vec![0; 5]).await;
    let reason = tokio::time::timeout(Duration::from_secs(2), client.closed())
        .await
        .unwrap();
    assert!(reason.contains("윈도"));
    assert_eq!(status.get(), TunnelState::Down);
    assert!(stream.receive().await.is_err());
}

#[tokio::test]
async fn tcp_half_close_allows_reply_after_local_fin_and_fin_is_not_a_reset() {
    let (client, mut peer, _) = setup(Settings::default(), Settings::default(), Limits::default());
    let stream = opened(&client, &mut peer, StreamKind::Tcp).await;
    let id = stream.id();
    stream.send_tcp(b"request").await.unwrap();
    stream.finish().await.unwrap();
    assert_eq!(next(&mut peer).await.kind, FrameType::TcpData);
    assert_eq!(next(&mut peer).await.kind, FrameType::TcpFin);
    send(&mut peer, FrameType::TcpData, id, b"response".to_vec()).await;
    send(&mut peer, FrameType::TcpFin, id, Vec::new()).await;
    assert_eq!(stream.receive().await.unwrap().unwrap(), b"response");
    assert!(stream.receive().await.unwrap().is_none());
    assert!(stream.send_tcp(b"late").await.is_err());
    drop(stream);
    assert_eq!(client.active_streams(), 0);
    assert!(client.is_connected());
}

#[tokio::test]
async fn slow_stream_queue_resets_it_without_blocking_other_streams() {
    let limits = Limits {
        queued_frames_per_stream: 2,
        ..Limits::default()
    };
    let (client, mut peer, _) = setup(Settings::default(), Settings::default(), limits);
    let slow = opened(&client, &mut peer, StreamKind::Tcp).await;
    let fast = opened(&client, &mut peer, StreamKind::Tcp).await;
    for _ in 0..3 {
        send(&mut peer, FrameType::TcpData, slow.id(), b"x".to_vec()).await;
    }
    send(&mut peer, FrameType::TcpData, fast.id(), b"fast".to_vec()).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), fast.receive())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        b"fast"
    );
    assert!(slow.receive().await.is_err());
    assert!(client.is_connected());
    assert_eq!(client.active_streams(), 1);
    let reset = next(&mut peer).await;
    assert_eq!(reset.kind, FrameType::StreamReset);
    assert_eq!(reset.stream_id, slow.id());
    assert_eq!(
        ErrorMessage::decode(&reset.payload).unwrap().code,
        ErrorCode::Capacity
    );
}

#[tokio::test]
async fn open_error_retires_one_stream_and_next_id_is_not_reused() {
    let (client, mut peer, _) = setup(Settings::default(), Settings::default(), Limits::default());
    let opening = client.open_tcp(target());
    let rejecting = async {
        let request = next(&mut peer).await;
        assert_eq!(request.stream_id, 1);
        send(
            &mut peer,
            FrameType::OpenError,
            1,
            ErrorMessage::new(ErrorCode::Refused, "연결 거부")
                .encode()
                .unwrap(),
        )
        .await;
    };
    let (result, _) = tokio::join!(opening, rejecting);
    assert!(result.is_err());
    assert!(client.is_connected());
    let stream = opened(&client, &mut peer, StreamKind::Tcp).await;
    assert_eq!(stream.id(), 3);
}

#[tokio::test]
async fn cancellation_of_pending_open_sends_reset_and_frees_capacity() {
    let limits = Limits {
        max_streams: 1,
        ..Limits::default()
    };
    let (client, mut peer, _) = setup(Settings::default(), Settings::default(), limits);
    let opening = {
        let client = client.clone();
        tokio::spawn(async move { client.open_udp(target()).await })
    };
    let request = next(&mut peer).await;
    opening.abort();
    assert!(opening.await.err().unwrap().is_cancelled());
    let reset = next(&mut peer).await;
    assert_eq!(reset.kind, FrameType::StreamReset);
    assert_eq!(reset.stream_id, request.stream_id);
    assert_eq!(client.active_streams(), 0);
    let stream = opened(&client, &mut peer, StreamKind::Udp).await;
    assert_eq!(stream.id(), 3);
}

#[tokio::test]
async fn cancelled_tcp_send_resets_stream_and_wakes_credit_waiter() {
    let (client, mut peer, _) = setup(small_settings(), Settings::default(), Limits::default());
    let stream = opened(&client, &mut peer, StreamKind::Tcp).await;
    let sending = {
        let stream = Arc::clone(&stream);
        tokio::spawn(async move { stream.send_tcp(b"abcdefgh").await })
    };
    assert_eq!(next(&mut peer).await.payload, b"abcd");
    sending.abort();
    assert!(sending.await.unwrap_err().is_cancelled());
    let reset = next(&mut peer).await;
    assert_eq!(reset.kind, FrameType::StreamReset);
    assert_eq!(client.active_streams(), 0);
    assert!(stream.send_tcp(b"more").await.is_err());
    assert!(client.is_connected());
}

#[tokio::test]
async fn tunnel_loss_wakes_receivers_and_senders_without_direct_fallback() {
    let (client, mut peer, status) =
        setup(small_settings(), Settings::default(), Limits::default());
    let stream = opened(&client, &mut peer, StreamKind::Tcp).await;
    let sending = {
        let stream = Arc::clone(&stream);
        tokio::spawn(async move { stream.send_tcp(b"abcdefgh").await })
    };
    next(&mut peer).await;
    drop(peer);
    tokio::time::timeout(Duration::from_secs(2), client.closed())
        .await
        .unwrap();
    assert_eq!(status.get(), TunnelState::Down);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), sending)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(stream.receive().await.is_err());
}

#[tokio::test]
async fn data_before_open_ok_is_protocol_error() {
    let (client, mut peer, _) = setup(Settings::default(), Settings::default(), Limits::default());
    let opening = client.open_tcp(target());
    let malformed = async {
        let request = next(&mut peer).await;
        send(&mut peer, FrameType::TcpData, request.stream_id, vec![1]).await;
    };
    let (result, _) = tokio::join!(opening, malformed);
    assert!(result.is_err());
    assert!(!client.is_connected());
}

#[tokio::test]
async fn dns_rpc_checks_id_and_releases_transaction() {
    let (client, mut peer, _) = setup(Settings::default(), Settings::default(), Limits::default());
    let query = vec![0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let querying = client.query_dns(&query);
    let responding = async {
        let request = next(&mut peer).await;
        assert_eq!(request.kind, FrameType::DnsQuery);
        let mut response = request.payload;
        response[2] |= 0x80;
        send(
            &mut peer,
            FrameType::DnsResponse,
            request.stream_id,
            response.clone(),
        )
        .await;
        response
    };
    let (response, expected) = tokio::join!(querying, responding);
    assert_eq!(response.unwrap(), expected);
    assert_eq!(client.active_streams(), 0);
}

#[tokio::test]
async fn wrong_dns_id_fails_connection() {
    let (client, mut peer, _) = setup(Settings::default(), Settings::default(), Limits::default());
    let query = vec![0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let querying = client.query_dns(&query);
    let responding = async {
        let request = next(&mut peer).await;
        let mut response = request.payload;
        response[0] ^= 1;
        response[2] |= 0x80;
        send(
            &mut peer,
            FrameType::DnsResponse,
            request.stream_id,
            response,
        )
        .await;
    };
    let (response, _) = tokio::join!(querying, responding);
    assert!(response.is_err());
    assert!(!client.is_connected());
}

#[tokio::test]
async fn goaway_prevents_new_streams_but_existing_stream_can_receive() {
    let (client, mut peer, _) = setup(Settings::default(), Settings::default(), Limits::default());
    let stream = opened(&client, &mut peer, StreamKind::Tcp).await;
    send(
        &mut peer,
        FrameType::GoAway,
        0,
        ErrorMessage::new(ErrorCode::Cancelled, "종료 준비")
            .encode()
            .unwrap(),
    )
    .await;
    send(&mut peer, FrameType::TcpData, stream.id(), b"last".to_vec()).await;
    assert_eq!(stream.receive().await.unwrap().unwrap(), b"last");
    assert!(client.open_tcp(target()).await.is_err());
    assert!(client.is_connected());
}

#[tokio::test]
async fn heartbeat_does_not_discard_partially_received_frame() {
    let limits = Limits {
        ping_interval: Duration::from_millis(10),
        pong_timeout: Duration::from_secs(2),
        ..Limits::default()
    };
    let (client, mut peer, _) = setup(Settings::default(), Settings::default(), limits);
    let stream = opened(&client, &mut peer, StreamKind::Tcp).await;
    let mut bytes = Vec::new();
    Frame {
        kind: FrameType::TcpData,
        stream_id: stream.id(),
        payload: b"partial".to_vec(),
    }
    .write(&mut bytes)
    .unwrap();
    peer.write_all(&bytes[..7]).await.unwrap();
    let ping = transport::read_frame(&mut peer).await.unwrap();
    assert_eq!(ping.kind, FrameType::Ping);
    peer.write_all(&bytes[7..]).await.unwrap();
    send(&mut peer, FrameType::Pong, 0, ping.payload).await;
    assert_eq!(stream.receive().await.unwrap().unwrap(), b"partial");
    assert!(client.is_connected());
}

#[tokio::test]
async fn missing_pong_marks_session_down() {
    let limits = Limits {
        ping_interval: Duration::from_millis(10),
        pong_timeout: Duration::from_millis(100),
        ..Limits::default()
    };
    let (client, mut peer, status) = setup(Settings::default(), Settings::default(), limits);
    let ping = transport::read_frame(&mut peer).await.unwrap();
    assert_eq!(ping.kind, FrameType::Ping);
    let reason = tokio::time::timeout(Duration::from_secs(2), client.closed())
        .await
        .unwrap();
    assert!(reason.contains("PONG"));
    assert_eq!(status.get(), TunnelState::Down);
}

#[tokio::test]
async fn dropped_last_client_closes_io_without_a_background_reference_cycle() {
    let (client, mut peer, status) =
        setup(Settings::default(), Settings::default(), Limits::default());
    drop(client);
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), peer.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(status.get(), TunnelState::Down);
}

#[test]
fn error_text_truncation_keeps_utf8_and_unknown_codes_are_rejected() {
    let error = ErrorMessage::new(ErrorCode::Capacity, &"한".repeat(200));
    assert!(error.message.len() <= 256);
    assert_eq!(
        ErrorMessage::decode(&error.encode().unwrap()).unwrap(),
        error
    );
    assert!(ErrorMessage::decode(&[0xff, 0xff, 0, 0]).is_err());
}
