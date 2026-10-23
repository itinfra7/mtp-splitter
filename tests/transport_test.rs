//! 독립된 로컬 TCP 서버에서 Fake-TLS와 실제 TLS 상호 인증을 검증한다.
//! 이 파일의 고정 인증서와 개인키는 테스트에만 사용한다.

mod support;
use mtp_splitter::{
    mtproto_core::{self, ObfuscatedStream, TransportTag},
    protocol::{Frame, FrameType, Settings},
    transport::{self, FakeTlsIo},
};
use rand::{SeedableRng, rngs::StdRng};
use std::time::Duration;
use support::{Directory, secret, start_gateway_peer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn pair() -> (ObfuscatedStream, ObfuscatedStream) {
    let (wire, client) = ObfuscatedStream::client(
        &secret(),
        2,
        TransportTag::PaddedIntermediate,
        &mut StdRng::seed_from_u64(2),
    )
    .unwrap();
    let (_, server) =
        ObfuscatedStream::server(&wire, &secret(), TransportTag::PaddedIntermediate).unwrap();
    (client, server)
}

async fn start_peer() -> (
    mtp_splitter::config::ServerConfig,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    start_gateway_peer(Settings::default(), |mut secured| async move {
        let frame = transport::read_frame(&mut secured).await?;
        transport::write_frame(&mut secured, &frame).await?;
        secured.shutdown().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn asynchronous_cipher_stream_handles_small_buffers_and_large_bidirectional_payload() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (left, right) = tokio::io::duplex(37);
        let (client, server) = pair();
        let client = FakeTlsIo::from_authenticated(left, client);
        let mut server = FakeTlsIo::from_authenticated(right, server);
        let echo = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                let length = server.read(&mut buffer).await.unwrap();
                if length == 0 {
                    break;
                }
                server.write_all(&buffer[..length]).await.unwrap();
                server.flush().await.unwrap();
            }
            server.shutdown().await.unwrap();
        });
        let payload: Vec<_> = (0..262145).map(|i| i as u8).collect();
        let expected = payload.clone();
        let (mut reader, mut writer) = tokio::io::split(client);
        let sending = async move {
            writer.write_all(&payload).await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let receiving = async move {
            let mut output = Vec::new();
            reader.read_to_end(&mut output).await.unwrap();
            assert_eq!(output, expected);
        };
        tokio::join!(sending, receiving);
        echo.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn asynchronous_transport_rejects_oversized_plaintext_chunk_before_allocation() {
    let (left, mut right) = tokio::io::duplex(64);
    let (client, mut server) = pair();
    let mut client = FakeTlsIo::from_authenticated(left, client);
    let mut invalid = u32::MAX.to_le_bytes().to_vec();
    server.encrypt(&mut invalid);
    let mut record = Vec::new();
    mtproto_core::write_tls_records(&mut record, &invalid).unwrap();
    right.write_all(&record).await.unwrap();
    let mut buffer = [0; 1];
    assert_eq!(
        client.read(&mut buffer).await.unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn asynchronous_transport_reports_truncated_record() {
    let (left, mut right) = tokio::io::duplex(64);
    let (client, _) = pair();
    let mut client = FakeTlsIo::from_authenticated(left, client);
    right.write_all(&[0x17, 3, 3, 0, 4, 1, 2]).await.unwrap();
    right.shutdown().await.unwrap();
    let mut buffer = [0; 1];
    assert_eq!(
        client.read(&mut buffer).await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test]
async fn full_fake_tls_obfuscated_and_mutual_tls_handshake_exchanges_frames() {
    let dir = Directory::new();
    let (server, peer) = start_peer().await;
    let (mut io, settings) = transport::connect(&server, &dir.security(), &dir.paths)
        .await
        .unwrap();
    assert_eq!(settings.capabilities, 7);
    let frame = Frame {
        kind: FrameType::UdpDatagram,
        stream_id: 1,
        payload: vec![42; 60000],
    };
    transport::write_frame(&mut io, &frame).await.unwrap();
    assert_eq!(transport::read_frame(&mut io).await.unwrap(), frame);
    peer.await.unwrap().unwrap();
}

#[tokio::test]
async fn inner_tls_rejects_wrong_server_name() {
    let dir = Directory::new();
    let mut security = dir.security();
    security.server_name = "wrong.test".into();
    let (server, peer) = start_peer().await;
    assert!(
        transport::connect(&server, &security, &dir.paths)
            .await
            .is_err()
    );
    assert!(peer.await.unwrap().is_err());
}

#[tokio::test]
async fn inner_tls_rejects_untrusted_server_certificate() {
    let dir = Directory::new();
    let mut security = dir.security();
    security.ca_certificate = "config/client.pem".into();
    let (server, peer) = start_peer().await;
    assert!(
        transport::connect(&server, &security, &dir.paths)
            .await
            .is_err()
    );
    assert!(peer.await.unwrap().is_err());
}

#[tokio::test]
async fn mutual_tls_rejects_certificate_with_server_only_usage() {
    let dir = Directory::new();
    std::fs::write(
        dir.paths.resolve("config/client.pem").unwrap(),
        include_bytes!("fixtures/test-server.pem"),
    )
    .unwrap();
    std::fs::write(
        dir.paths.resolve("config/client-key.pem").unwrap(),
        include_bytes!("fixtures/test-server-key.pem"),
    )
    .unwrap();
    let (server, peer) = start_peer().await;
    assert!(
        transport::connect(&server, &dir.security(), &dir.paths)
            .await
            .is_err()
    );
    assert!(peer.await.unwrap().is_err());
}

#[test]
fn security_configuration_rejects_external_paths_and_missing_certificates() {
    let dir = Directory::new();
    let mut security = dir.security();
    security.client_key = "../outside.pem".into();
    assert!(security.tls_config(&dir.paths).is_err());
    security.client_key = "config/missing.pem".into();
    assert!(security.tls_config(&dir.paths).is_err());
}
