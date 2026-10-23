//! Fake-TLS·난독화 스트림 위에 상호 인증된 실제 TLS 1.3 연결을 연다.
//! 패킷 경계를 스트림 경계로 착각하지 않도록 모든 프레이밍을 증분 처리한다.

use crate::{
    config::{ServerConfig, TunnelMode},
    gateway_wire::{self, Negotiation, WireDialect},
    mtproto_core::{self, ObfuscatedStream, TransportTag},
    paths::AppPaths,
    protocol::{Frame, FrameType, Settings},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Cursor},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    #[serde(alias = "mux_version")]
    pub protocol_version: u8,
    pub server_name: String,
    #[serde(alias = "ca_file")]
    pub ca_certificate: String,
    #[serde(alias = "certificate_file")]
    pub client_certificate: String,
    #[serde(alias = "private_key_file")]
    pub client_key: String,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub zero_rtt: bool,
}

impl SecurityConfig {
    pub fn dialect(&self) -> WireDialect {
        if self.transport.as_deref() == Some("mtp_tcp_v1") {
            WireDialect::GatewayV1
        } else {
            WireDialect::Legacy
        }
    }
    pub fn load(paths: &AppPaths) -> Result<Self> {
        Ok(serde_json::from_slice(&std::fs::read(
            paths.resolve("config/security.json")?,
        )?)?)
    }
    fn validate_parameters(&self) -> Result<()> {
        ensure!(!self.zero_rtt, "0-RTT는 허용하지 않습니다");
        ensure!(
            self.transport
                .as_deref()
                .is_none_or(|value| value == "mtp_tcp_v1"),
            "지원하지 않는 게이트웨이 전송 형식입니다"
        );
        ensure!(
            self.protocol_version == 1,
            "지원하지 않는 게이트웨이 버전입니다"
        );
        ensure!(
            crate::fake_dns::normalize_domain(&self.server_name)? == self.server_name
                && !self.server_name.contains('_'),
            "내부 TLS 서버 이름이 잘못됐습니다"
        );
        Ok(())
    }
    pub fn tls_config(&self, paths: &AppPaths) -> Result<rustls::ClientConfig> {
        self.validate_parameters()?;
        let ca = std::fs::read(paths.resolve(&self.ca_certificate)?)?;
        let certs = std::fs::read(paths.resolve(&self.client_certificate)?)?;
        let key = zeroize::Zeroizing::new(std::fs::read(paths.resolve(&self.client_key)?)?);
        self.tls_config_from_pem(&ca, &certs, &key)
    }
    /// ZIP의 인증서를 메모리에서 검사하여 임시 개인키 파일을 만들지 않는다.
    pub(crate) fn tls_config_from_pem(
        &self,
        ca: &[u8],
        certs: &[u8],
        key: &[u8],
    ) -> Result<rustls::ClientConfig> {
        self.validate_parameters()?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut Cursor::new(ca)) {
            roots.add(cert?)?;
        }
        ensure!(!roots.is_empty(), "게이트웨이 CA 인증서가 없습니다");
        let certificates = rustls_pemfile::certs(&mut Cursor::new(certs))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(!certificates.is_empty(), "클라이언트 인증서가 없습니다");
        let private_key = rustls_pemfile::private_key(&mut Cursor::new(key))?
            .context("클라이언트 개인키가 없습니다")?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_client_auth_cert(certificates, private_key)?;
        config.enable_early_data = false;
        config.resumption = rustls::client::Resumption::disabled();
        config.alpn_protocols = vec![self.dialect().alpn().to_vec()];
        Ok(config)
    }
}

/// 암호화 방향은 한 번 초기화하며 동일 연결 동안 유지한다.
pub struct FakeTlsIo<S> {
    socket: S,
    cipher: ObfuscatedStream,
    header: [u8; 5],
    header_used: usize,
    record: Vec<u8>,
    record_used: usize,
    plaintext: Vec<u8>,
    plain_used: usize,
    content: Vec<u8>,
    content_used: usize,
    outgoing: Vec<u8>,
    outgoing_used: usize,
}

impl<S> FakeTlsIo<S> {
    pub fn from_authenticated(socket: S, cipher: ObfuscatedStream) -> Self {
        Self {
            socket,
            cipher,
            header: [0; 5],
            header_used: 0,
            record: Vec::new(),
            record_used: 0,
            plaintext: Vec::new(),
            plain_used: 0,
            content: Vec::new(),
            content_used: 0,
            outgoing: Vec::new(),
            outgoing_used: 0,
        }
    }
    pub fn socket(&self) -> &S {
        &self.socket
    }
}

impl<S: AsyncRead + Unpin> FakeTlsIo<S> {
    fn poll_record(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<Option<Vec<u8>>>> {
        while self.header_used < 5 {
            let mut read = ReadBuf::new(&mut self.header[self.header_used..]);
            match Pin::new(&mut self.socket).poll_read(cx, &mut read) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let length = read.filled().len();
                    if length == 0 {
                        return if self.header_used == 0 {
                            Poll::Ready(Ok(None))
                        } else {
                            Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                        };
                    }
                    self.header_used += length;
                }
            }
        }
        if self.header[..3] != [0x17, 3, 3] {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Fake-TLS 레코드 종류 오류",
            )));
        }
        let length = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
        if length > mtproto_core::MAX_TLS_RECORD {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Fake-TLS 레코드 크기 초과",
            )));
        }
        if self.record.len() != length {
            self.record.resize(length, 0);
        }
        while self.record_used < length {
            let mut read = ReadBuf::new(&mut self.record[self.record_used..]);
            match Pin::new(&mut self.socket).poll_read(cx, &mut read) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let count = read.filled().len();
                    if count == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    self.record_used += count;
                }
            }
        }
        self.header_used = 0;
        self.record_used = 0;
        Poll::Ready(Ok(Some(std::mem::take(&mut self.record))))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FakeTlsIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..32 {
            if this.content_used < this.content.len() {
                let count = output
                    .remaining()
                    .min(this.content.len() - this.content_used);
                output.put_slice(&this.content[this.content_used..this.content_used + count]);
                this.content_used += count;
                return Poll::Ready(Ok(()));
            }
            this.content.clear();
            this.content_used = 0;
            let available = &this.plaintext[this.plain_used..];
            if available.len() >= 4 {
                let length =
                    u32::from_le_bytes(available[..4].try_into().expect("검증한 길이")) as usize;
                if !(9..=16403).contains(&length) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "난독화 청크 크기 오류",
                    )));
                }
                if available.len() >= length + 4 {
                    this.content =
                        match mtproto_core::decode_extended_chunk(&available[..length + 4]) {
                            Ok(content) => content.to_vec(),
                            Err(error) => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    error,
                                )));
                            }
                        };
                    this.plain_used += length + 4;
                    if this.plain_used >= 16384 {
                        this.plaintext.drain(..this.plain_used);
                        this.plain_used = 0;
                    }
                    continue;
                }
            }
            match this.poll_record(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(None)) => {
                    if this.plain_used != this.plaintext.len() {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(mut bytes))) => {
                    if this.plaintext.len() - this.plain_used + bytes.len() > 32791 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "난독화 수신 버퍼 한도 초과",
                        )));
                    }
                    this.cipher.decrypt(&mut bytes);
                    this.plaintext.extend_from_slice(&bytes);
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<S: AsyncWrite + Unpin> FakeTlsIo<S> {
    fn poll_drain(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        while self.outgoing_used < self.outgoing.len() {
            match Pin::new(&mut self.socket).poll_write(cx, &self.outgoing[self.outgoing_used..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(count)) => self.outgoing_used += count,
            }
        }
        self.outgoing.clear();
        self.outgoing_used = 0;
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for FakeTlsIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => (),
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = bytes.len().min(16384);
        let mut chunk =
            match mtproto_core::encode_extended_chunk(&bytes[..count], &mut rand::rngs::OsRng) {
                Ok(bytes) => bytes,
                Err(error) => return Poll::Ready(Err(io::Error::other(error))),
            };
        this.cipher.encrypt(&mut chunk);
        if let Err(error) = mtproto_core::write_tls_records(&mut this.outgoing, &chunk) {
            return Poll::Ready(Err(io::Error::other(error)));
        }
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Pin::new(&mut this.socket).poll_flush(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.get_mut().socket).poll_shutdown(cx),
        }
    }
}

pub type GatewayIo = TlsStream<FakeTlsIo<TcpStream>>;

pub async fn connect(
    server: &ServerConfig,
    security: &SecurityConfig,
    paths: &AppPaths,
) -> Result<(GatewayIo, Settings)> {
    let (io, negotiation) = connect_detailed(server, security, paths).await?;
    Ok((io, negotiation.settings))
}

pub async fn connect_detailed(
    server: &ServerConfig,
    security: &SecurityConfig,
    paths: &AppPaths,
) -> Result<(GatewayIo, Negotiation)> {
    ensure!(
        server.tunnel_mode == TunnelMode::ExtendedSocksOverMtproto,
        "이 연결은 전용 확장 게이트웨이 모드입니다"
    );
    let timeout = Duration::from_secs(server.timeout_seconds);
    tokio::time::timeout(timeout, async {
        let dialect = security.dialect();
        let io = connect_outer_for(server, dialect).await?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(security.tls_config(paths)?));
        let name = rustls::pki_types::ServerName::try_from(security.server_name.clone())?;
        let mut secured = connector
            .connect(name, io)
            .await
            .context("게이트웨이 내부 TLS 1.3 상호 인증 실패")?;
        ensure!(
            secured.get_ref().1.alpn_protocol() == Some(dialect.alpn()),
            "게이트웨이 ALPN이 일치하지 않습니다"
        );
        gateway_wire::write_client(
            &mut secured,
            dialect,
            &Frame {
                kind: FrameType::Hello,
                stream_id: 0,
                payload: dialect.local_settings().encode()?,
            },
        )
        .await?;
        let welcome = gateway_wire::read_server(&mut secured, dialect).await?;
        ensure!(
            welcome.kind == FrameType::Welcome,
            "WELCOME 응답이 필요합니다"
        );
        let settings = dialect.welcome(&welcome.payload)?;
        Ok((secured, settings))
    })
    .await
    .context("게이트웨이 연결 제한 시간 초과")?
}

/// 외부 Fake-TLS 응답을 인증한 뒤 난독화 스트림을 준비한다.
/// 호출자는 전체 핸드셰이크에 제한 시간을 적용해야 한다.
pub async fn connect_outer(server: &ServerConfig) -> Result<FakeTlsIo<TcpStream>> {
    connect_outer_for(server, WireDialect::Legacy).await
}

pub async fn connect_outer_for(
    server: &ServerConfig,
    dialect: WireDialect,
) -> Result<FakeTlsIo<TcpStream>> {
    let secret = server.validate()?;
    let mut socket =
        TcpStream::connect(SocketAddr::new(server.endpoint_ip()?, server.port)).await?;
    socket.set_nodelay(true)?;
    let hello = mtproto_core::ClientHello::generate(
        &secret,
        u32::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?,
        &mut rand::rngs::OsRng,
    )?;
    socket.write_all(&hello.wire).await?;
    let mut response = Vec::new();
    for expected in [0x16, 0x14, 0x17] {
        let mut header = [0; 5];
        socket.read_exact(&mut header).await?;
        ensure!(
            header[..3] == [expected, 3, 3],
            "서버 Fake-TLS 레코드 순서 오류"
        );
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        ensure!(
            response.len() + 5 + length <= 65536,
            "서버 Fake-TLS 응답 크기 초과"
        );
        response.extend_from_slice(&header);
        let start = response.len();
        response.resize(start + length, 0);
        socket.read_exact(&mut response[start..]).await?;
    }
    mtproto_core::verify_server_hello(&secret, &hello, &response)?;
    let (init, cipher) = ObfuscatedStream::client(
        &secret,
        if dialect == WireDialect::GatewayV1 {
            0
        } else {
            server.dc_id
        },
        TransportTag::PaddedIntermediate,
        &mut rand::rngs::OsRng,
    )?;
    socket.write_all(&[0x14, 3, 3, 0, 1, 1]).await?;
    let mut records = Vec::new();
    mtproto_core::write_tls_records(&mut records, &init)?;
    socket.write_all(&records).await?;
    Ok(FakeTlsIo::from_authenticated(socket, cipher))
}

pub async fn write_frame(writer: &mut (impl AsyncWrite + Unpin), frame: &Frame) -> Result<()> {
    let mut bytes = Vec::new();
    frame.write(&mut bytes)?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}
pub async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> Result<Frame> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix).await?;
    let length = u32::from_be_bytes(prefix) as usize;
    ensure!(
        (8..=crate::protocol::MAX_FRAME).contains(&length),
        "게이트웨이 프레임 길이 오류"
    );
    let mut bytes = Vec::with_capacity(length + 4);
    bytes.extend_from_slice(&prefix);
    bytes.resize(length + 4, 0);
    reader.read_exact(&mut bytes[4..]).await?;
    Frame::read(&mut Cursor::new(bytes))
}
