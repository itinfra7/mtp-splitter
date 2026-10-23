//! 별도로 작성한 바이트 피어로 운영 게이트웨이 규격의 경계와 흐름 제어를 검증한다.

use mtp_splitter::{
    fake_dns,
    gateway::{GatewayClient, GatewayStream, Limits},
    gateway_wire::{self, WireDialect},
    nat_engine::TunnelStatus,
    protocol::{Frame, FrameType, Target, TargetAddress},
};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

fn target() -> Target {
    Target {
        address: TargetAddress::Ip("203.0.113.1".parse().unwrap()),
        port: 443,
    }
}
fn setup() -> (GatewayClient, DuplexStream) {
    let (io, peer) = tokio::io::duplex(1024 * 1024);
    let settings = WireDialect::GatewayV1.local_settings();
    let client = GatewayClient::attach_with_dialect(
        io,
        settings.clone(),
        settings,
        Arc::new(TunnelStatus::default()),
        Limits::default(),
        WireDialect::GatewayV1,
        (2, 2),
    )
    .unwrap();
    (client, peer)
}
async fn raw(peer: &mut DuplexStream, kind: u8, id: u32, payload: &[u8]) {
    let mut bytes = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(&[1, kind, 0, 0]);
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(payload);
    peer.write_all(&bytes).await.unwrap();
}
async fn next(peer: &mut DuplexStream) -> (u8, u32, Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(3), async {
        let length = peer.read_u32().await.unwrap() as usize;
        assert!((8..=262144).contains(&length));
        let mut bytes = vec![0; length];
        peer.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[2..4], &[0, 0]);
        (
            bytes[1],
            u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            bytes[8..].to_vec(),
        )
    })
    .await
    .unwrap()
}
async fn opened(client: &GatewayClient, peer: &mut DuplexStream, udp: bool) -> Arc<GatewayStream> {
    let opening = async {
        if udp {
            client.open_udp(target()).await
        } else {
            client.open_tcp(target()).await
        }
    };
    let response = async {
        let (kind, id, addr) = next(peer).await;
        assert_eq!(kind, if udp { 0x11 } else { 0x10 });
        assert_eq!(addr, target().encode().unwrap());
        let mut payload = Target {
            port: 30000,
            ..target()
        }
        .encode()
        .unwrap();
        payload.extend_from_slice(&addr);
        raw(peer, 0x12, id, &payload).await;
    };
    let (stream, _) = tokio::join!(opening, response);
    stream.unwrap()
}
fn query(id: u8) -> Vec<u8> {
    let mut bytes = vec![0, id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    fake_dns::encode_name("example.com", &mut bytes).unwrap();
    bytes.extend_from_slice(&[0, 1, 0, 1]);
    bytes
}

#[tokio::test]
async fn hello_welcome_and_control_codes_match_independent_wire_bytes() {
    let dialect = WireDialect::GatewayV1;
    assert_eq!(dialect.alpn(), b"mtp-gateway/1");
    let settings = dialect.local_settings();
    let (mut client, mut peer) = tokio::io::duplex(1024);
    gateway_wire::write_client(
        &mut client,
        dialect,
        &Frame {
            kind: FrameType::Hello,
            stream_id: 0,
            payload: settings.encode().unwrap(),
        },
    )
    .await
    .unwrap();
    let (kind, id, payload) = next(&mut peer).await;
    assert_eq!((kind, id), (1, 0));
    assert_eq!(payload, hex::decode("000800000002000000000007").unwrap());
    let welcome = hex::decode("0008000000020000000000070080010000000078").unwrap();
    raw(&mut peer, 2, 0, &welcome).await;
    let frame = gateway_wire::read_server(&mut client, dialect)
        .await
        .unwrap();
    let negotiated = dialect.welcome(&frame.payload).unwrap();
    assert_eq!(negotiated.settings, settings);
    assert_eq!(
        (
            negotiated.tcp_limit,
            negotiated.udp_limit,
            negotiated.udp_idle_seconds
        ),
        (128, 256, 120)
    );
    raw(&mut peer, 0x30, 0, &[9; 8]).await;
    assert_eq!(
        gateway_wire::read_server(&mut client, dialect)
            .await
            .unwrap()
            .kind,
        FrameType::Ping
    );
    raw(&mut peer, 0x24, 1, &64u32.to_be_bytes()).await;
    assert_eq!(
        gateway_wire::read_server(&mut client, dialect)
            .await
            .unwrap()
            .kind,
        FrameType::WindowUpdate
    );
    assert!(dialect.welcome(&welcome[..19]).is_err());
}

#[tokio::test]
async fn udp_accepts_empty_and_maximum_datagrams_and_returns_full_wire_credit() {
    let (client, mut peer) = setup();
    let udp = opened(&client, &mut peer, true).await;
    for data in [Vec::new(), vec![0x5a; 65507]] {
        udp.send_datagram(&data).await.unwrap();
        assert_eq!(next(&mut peer).await, (0x21, udp.id(), data.clone()));
        let mut wire = target().encode().unwrap();
        wire.extend_from_slice(&data);
        raw(&mut peer, 0x21, udp.id(), &wire).await;
        assert_eq!(udp.receive().await.unwrap(), Some(data));
        let amount = (wire.len() as u32 + 64).to_be_bytes().to_vec();
        let a = next(&mut peer).await;
        let b = next(&mut peer).await;
        assert_eq!(a, (0x24, udp.id(), amount.clone()));
        assert_eq!(b, (0x24, 0, amount));
    }
    assert!(client.is_connected());
}

#[tokio::test]
async fn unexpected_udp_source_closes_tunnel_before_delivery() {
    let (client, mut peer) = setup();
    let udp = opened(&client, &mut peer, true).await;
    let bad = Target {
        port: 444,
        ..target()
    }
    .encode()
    .unwrap();
    raw(&mut peer, 0x21, udp.id(), &bad).await;
    assert!(udp.receive().await.is_err());
    assert!(!client.is_connected());
}

#[tokio::test]
async fn dns_rpc_uses_stream_zero_and_correlates_out_of_order_responses() {
    let (client, mut peer) = setup();
    let a = query(1);
    let b = query(2);
    let answering = async {
        let first = next(&mut peer).await;
        let second = next(&mut peer).await;
        assert_eq!((first.0, first.1), (0x40, 0));
        assert_eq!((second.0, second.1), (0x40, 0));
        assert_ne!(&first.2[..4], &second.2[..4]);
        for (_, _, request) in [second, first] {
            let mut response = request[..4].to_vec();
            response.extend_from_slice(&[0, 0]);
            let mut wire = request[4..].to_vec();
            wire[2] |= 0x80;
            response.extend_from_slice(&wire);
            raw(&mut peer, 0x41, 0, &response).await;
        }
    };
    let (ra, rb, _) = tokio::join!(client.query_dns(&a), client.query_dns(&b), answering);
    assert_eq!(ra.unwrap()[1], 1);
    assert_eq!(rb.unwrap()[1], 2);
    assert_eq!(client.active_streams(), 0);
}

#[tokio::test]
async fn dns_failure_is_isolated_and_does_not_emit_reset_for_a_dns_request() {
    let (client, mut peer) = setup();
    let q = query(3);
    let answering = async {
        let (_, _, request) = next(&mut peer).await;
        let mut error = request[..4].to_vec();
        error.extend_from_slice(&5u16.to_be_bytes());
        raw(&mut peer, 0x41, 0, &error).await;
    };
    let (result, _) = tokio::join!(client.query_dns(&q), answering);
    assert!(result.is_err());
    assert_eq!(client.active_streams(), 0);
    assert!(client.is_connected());
    assert!(
        tokio::time::timeout(Duration::from_millis(30), peer.read_u8())
            .await
            .is_err()
    );
    let _tcp = opened(&client, &mut peer, false).await;
}

#[tokio::test]
async fn dns_question_mismatch_and_truncated_resource_record_are_rejected() {
    for malformed in [false, true] {
        let (client, mut peer) = setup();
        let q = query(4);
        let answering = async {
            let (_, _, request) = next(&mut peer).await;
            let mut wire = request[4..].to_vec();
            wire[2] |= 0x80;
            if malformed {
                wire[7] = 1;
                wire.extend_from_slice(&[0xc0, 0x0c, 0]);
            } else {
                let end = wire.len();
                wire[end - 3] = 28;
            }
            let mut response = request[..4].to_vec();
            response.extend_from_slice(&[0, 0]);
            response.extend_from_slice(&wire);
            raw(&mut peer, 0x41, 0, &response).await;
        };
        let (result, _) = tokio::join!(client.query_dns(&q), answering);
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn empty_udp_exhausts_credit_and_resumes_only_after_stream_and_connection_updates() {
    let (io, mut peer) = tokio::io::duplex(1024 * 1024);
    let mut settings = WireDialect::GatewayV1.local_settings();
    settings.connection_credit = 131072;
    let client = GatewayClient::attach_with_dialect(
        io,
        settings.clone(),
        settings,
        Arc::new(TunnelStatus::default()),
        Limits::default(),
        WireDialect::GatewayV1,
        (2, 2),
    )
    .unwrap();
    let udp = opened(&client, &mut peer, true).await;
    for _ in 0..2048 {
        udp.send_datagram(&[]).await.unwrap();
        assert_eq!(next(&mut peer).await, (0x21, udp.id(), vec![]));
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), udp.send_datagram(&[]))
            .await
            .is_err()
    );
    raw(&mut peer, 0x24, udp.id(), &64u32.to_be_bytes()).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(30), udp.send_datagram(&[]))
            .await
            .is_err()
    );
    raw(&mut peer, 0x24, 0, &64u32.to_be_bytes()).await;
    udp.send_datagram(&[]).await.unwrap();
    assert_eq!(next(&mut peer).await, (0x21, udp.id(), vec![]));
    assert!(client.is_connected());
}
