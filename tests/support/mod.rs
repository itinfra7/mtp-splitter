//! 테스트 전용 CA·Fake-TLS 서버를 공유한다. 운영 서버 구현으로 배포하지 않는다.

use anyhow::{Result, ensure};
use hmac::{Hmac, Mac};
use mtp_splitter::{
    config::ServerConfig,
    mtproto_core::{ObfuscatedStream, ProxySecret, TransportTag},
    paths::AppPaths,
    protocol::{Frame, FrameType, Settings},
    transport::{self, FakeTlsIo, SecurityConfig},
};
use sha2::Sha256;
use std::{
    future::Future,
    io::Cursor,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub fn secret() -> ProxySecret {
    ProxySecret::parse("ee000102030405060708090a0b0c0d0e0f6578616d706c652e636f6d").unwrap()
}
pub struct Directory {
    pub root: PathBuf,
    pub paths: AppPaths,
}
impl Directory {
    pub fn new() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("runtime/tmp")
            .join(format!(
                "transport-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
        std::fs::create_dir_all(&root).unwrap();
        let paths = AppPaths::new(root.clone()).unwrap();
        paths.prepare().unwrap();
        for (name, bytes) in [
            (
                "config/ca.pem",
                include_bytes!("../fixtures/test-ca.pem").as_slice(),
            ),
            (
                "config/client.pem",
                include_bytes!("../fixtures/test-client.pem").as_slice(),
            ),
            (
                "config/client-key.pem",
                include_bytes!("../fixtures/test-client-key.pem").as_slice(),
            ),
        ] {
            std::fs::write(paths.resolve(name).unwrap(), bytes).unwrap();
        }
        Self { root, paths }
    }
    pub fn security(&self) -> SecurityConfig {
        SecurityConfig {
            protocol_version: 1,
            server_name: "gateway.test".into(),
            ca_certificate: "config/ca.pem".into(),
            client_certificate: "config/client.pem".into(),
            client_key: "config/client-key.pem".into(),
            transport: None,
            zero_rtt: false,
        }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .unwrap();
        let root = self.root.canonicalize().unwrap();
        assert!(root.starts_with(workspace.join("runtime/tmp")));
        std::fs::remove_dir_all(root).unwrap();
    }
}

fn server_config() -> rustls::ServerConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut Cursor::new(include_bytes!("../fixtures/test-ca.pem"))) {
        roots.add(cert.unwrap()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::clone(&provider),
    )
    .build()
    .unwrap();
    let certs = rustls_pemfile::certs(&mut Cursor::new(include_bytes!(
        "../fixtures/test-server.pem"
    )))
    .collect::<std::result::Result<Vec<_>, _>>()
    .unwrap();
    let key = rustls_pemfile::private_key(&mut Cursor::new(include_bytes!(
        "../fixtures/test-server-key.pem"
    )))
    .unwrap()
    .unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .unwrap();
    config.alpn_protocols = vec![b"mtp-splitter/1".to_vec()];
    config
}

async fn accept_outer(mut socket: TcpStream) -> Result<FakeTlsIo<TcpStream>> {
    let mut header = [0; 5];
    socket.read_exact(&mut header).await?;
    ensure!(header[..3] == [0x16, 3, 1], "클라이언트 Fake-TLS 헤더 오류");
    let size = usize::from(u16::from_be_bytes([header[3], header[4]]));
    ensure!((76..=2048).contains(&size), "클라이언트 크기 오류");
    let mut client = header.to_vec();
    client.resize(size + 5, 0);
    socket.read_exact(&mut client[5..]).await?;
    let random = client[11..43].to_vec();
    let sid = client[44..76].to_vec();
    client[11..43].fill(0);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret().key())?;
    mac.update(&client);
    let expected = mac.finalize().into_bytes();
    ensure!(
        expected[..28] == random[..28],
        "테스트 클라이언트 HMAC 오류"
    );
    let mut timestamp = [0; 4];
    for index in 0..4 {
        timestamp[index] = expected[28 + index] ^ random[28 + index];
    }
    let now = u32::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    ensure!(
        now.abs_diff(u32::from_le_bytes(timestamp)) <= 300,
        "테스트 클라이언트 타임스탬프 오류"
    );
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/fake_tls.json"))?;
    let mut server = hex::decode(fixture["server"].as_str().unwrap())?;
    server[11..43].fill(0);
    server[44..76].copy_from_slice(&sid);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret().key())?;
    mac.update(&random);
    mac.update(&server);
    server[11..43].copy_from_slice(&mac.finalize().into_bytes());
    for bytes in server.chunks(3) {
        socket.write_all(bytes).await?;
    }
    let mut ccs = [0; 6];
    socket.read_exact(&mut ccs).await?;
    ensure!(ccs == [0x14, 3, 3, 0, 1, 1], "CCS 오류");
    let mut header = [0; 5];
    socket.read_exact(&mut header).await?;
    ensure!(header == [0x17, 3, 3, 0, 64], "초기화 레코드 오류");
    let mut init = [0; 64];
    socket.read_exact(&mut init).await?;
    let (_, cipher) = ObfuscatedStream::server(&init, &secret(), TransportTag::PaddedIntermediate)?;
    Ok(FakeTlsIo::from_authenticated(socket, cipher))
}

pub type TestGatewayIo = tokio_rustls::server::TlsStream<FakeTlsIo<TcpStream>>;
pub async fn start_gateway_peer<F, Fut>(
    settings: Settings,
    handler: F,
) -> (ServerConfig, tokio::task::JoinHandle<Result<()>>)
where
    F: FnOnce(TestGatewayIo) -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let mut config: ServerConfig =
        serde_json::from_str(include_str!("../../examples/config/server.json")).unwrap();
    config.host = endpoint.ip().to_string();
    config.port = endpoint.port();
    config.timeout_seconds = 3;
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let io = accept_outer(socket).await?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config()));
        let mut secured = acceptor.accept(io).await?;
        ensure!(
            secured
                .get_ref()
                .1
                .peer_certificates()
                .is_some_and(|chain| !chain.is_empty()),
            "클라이언트 인증서가 없습니다"
        );
        let hello = transport::read_frame(&mut secured).await?;
        ensure!(hello.kind == FrameType::Hello, "HELLO가 없습니다");
        Settings::decode(&hello.payload)?;
        transport::write_frame(
            &mut secured,
            &Frame {
                kind: FrameType::Welcome,
                stream_id: 0,
                payload: settings.encode()?,
            },
        )
        .await?;
        handler(secured).await
    });
    (config, task)
}
