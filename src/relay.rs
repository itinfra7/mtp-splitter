//! 루프백 TCP·UDP 릴레이, Fake-IP 수명과 원격 DNS를 게이트웨이 스트림에 연결한다.

use crate::{
    config::ServerConfig,
    fake_dns::{self, FakeIpCache},
    gateway::{GatewayClient, Limits as GatewayLimits},
    nat_engine::{NatSession, NatSessionTable, TunnelState, TunnelStatus},
    packet::Protocol,
    paths::AppPaths,
    protocol::{MAX_DATAGRAM, Target, TargetAddress},
    transport::SecurityConfig,
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::JoinSet,
};

#[derive(Default)]
pub struct GatewaySlot {
    client: Mutex<Option<GatewayClient>>,
}
impl GatewaySlot {
    pub fn current(&self) -> Result<GatewayClient> {
        let client = self
            .client
            .lock()
            .map_err(|_| anyhow::anyhow!("게이트웨이 선택 잠금 손상"))?
            .clone()
            .context("연결된 게이트웨이가 없습니다")?;
        ensure!(client.is_connected(), "게이트웨이가 끊겼습니다");
        Ok(client)
    }
    pub fn install(&self, client: GatewayClient) -> Result<()> {
        ensure!(
            client.is_connected(),
            "끊긴 게이트웨이는 설치할 수 없습니다"
        );
        let mut slot = self
            .client
            .lock()
            .map_err(|_| anyhow::anyhow!("게이트웨이 선택 잠금 손상"))?;
        ensure!(slot.is_none(), "이전 게이트웨이를 먼저 종료해야 합니다");
        *slot = Some(client);
        Ok(())
    }
    pub fn clear(&self, reason: &str) {
        let previous = self.client.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(client) = previous {
            client.close(reason);
        }
    }
}

pub struct DnsService {
    cache: Arc<Mutex<FakeIpCache>>,
    paths: Arc<AppPaths>,
    gateways: Arc<GatewaySlot>,
}
pub struct ResolvedTarget {
    target: Target,
    _lease: Option<FakeIpLease>,
}
impl ResolvedTarget {
    pub fn target(&self) -> &Target {
        &self.target
    }
}
struct FakeIpLease {
    cache: Arc<Mutex<FakeIpCache>>,
    ip: Ipv4Addr,
}
impl Drop for FakeIpLease {
    fn drop(&mut self) {
        if let Ok(mut cache) = self.cache.lock()
            && let Err(error) = cache.unpin(self.ip)
        {
            tracing::error!(%error, "Fake-IP 참조 해제 실패");
        }
    }
}
impl DnsService {
    pub fn new(
        cache: Arc<Mutex<FakeIpCache>>,
        paths: Arc<AppPaths>,
        gateways: Arc<GatewaySlot>,
    ) -> Self {
        Self {
            cache,
            paths,
            gateways,
        }
    }
    pub fn resolve_target(&self, address: SocketAddr) -> Result<ResolvedTarget> {
        ensure!(address.port() != 0, "목적지 포트가 0입니다");
        if let IpAddr::V4(ip) = address.ip()
            && fake_dns::is_fake(ip)
        {
            let domain = self
                .cache
                .lock()
                .map_err(|_| anyhow::anyhow!("Fake-IP 캐시 잠금 손상"))?
                .pin(ip)?;
            return Ok(ResolvedTarget {
                target: Target {
                    address: TargetAddress::Domain(domain),
                    port: address.port(),
                },
                _lease: Some(FakeIpLease {
                    cache: Arc::clone(&self.cache),
                    ip,
                }),
            });
        }
        Ok(ResolvedTarget {
            target: Target {
                address: TargetAddress::Ip(address.ip()),
                port: address.port(),
            },
            _lease: None,
        })
    }
    pub async fn answer(&self, query: Vec<u8>) -> Result<Vec<u8>> {
        let question = fake_dns::parse_question(&query)?;
        if question.qclass == 1 && matches!(question.qtype, 1 | 28) {
            let cache = Arc::clone(&self.cache);
            let paths = Arc::clone(&self.paths);
            return tokio::task::spawn_blocking(move || {
                let mut cache = cache
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Fake-IP 캐시 잠금 손상"))?;
                let response = fake_dns::synthesize(
                    &query,
                    &mut cache,
                    SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                )?;
                // 응답을 보내기 전에 고수위 주소를 저장해 재시작 후 오래된 IP의 재할당을 막는다.
                cache.persist(&paths)?;
                Ok(response)
            })
            .await
            .context("DNS 캐시 저장 작업이 중단됐습니다")?;
        }
        if let Ok(gateway) = self.gateways.current() {
            match gateway.query_dns(&query).await {
                Ok(response) => return Ok(response),
                Err(error) => tracing::debug!(%error, "원격 DNS 실패"),
            }
        }
        Ok(fake_dns::error_response(&query, 2)?)
    }
    pub async fn serve_tcp(&self, socket: TcpStream, idle: Duration) -> Result<()> {
        let mut local = ResetOnFailure::new(socket);
        loop {
            let request = tokio::time::timeout(idle, async {
                let mut prefix = [0; 2];
                if local.socket.read(&mut prefix[..1]).await? == 0 {
                    return Ok::<_, anyhow::Error>(None);
                }
                local.socket.read_exact(&mut prefix[1..]).await?;
                let length = usize::from(u16::from_be_bytes(prefix));
                ensure!(length >= 12, "TCP DNS 요청이 너무 짧습니다");
                let mut query = vec![0; length];
                local.socket.read_exact(&mut query).await?;
                Ok(Some(query))
            })
            .await
            .context("TCP DNS 유휴 제한 시간 초과")??;
            let Some(request) = request else {
                local.graceful = true;
                return Ok(());
            };
            let response = self.answer(request).await?;
            tokio::time::timeout(idle, async {
                local
                    .socket
                    .write_all(&u16::try_from(response.len())?.to_be_bytes())
                    .await?;
                local.socket.write_all(&response).await?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .context("TCP DNS 응답 쓰기 제한 시간 초과")??;
        }
    }
}

struct ResetOnFailure {
    socket: TcpStream,
    graceful: bool,
}
impl ResetOnFailure {
    fn new(socket: TcpStream) -> Self {
        Self {
            socket,
            graceful: false,
        }
    }
}
impl Drop for ResetOnFailure {
    fn drop(&mut self) {
        if !self.graceful
            && let Err(error) =
                socket2::SockRef::from(&self.socket).set_linger(Some(Duration::ZERO))
        {
            tracing::debug!(%error, "로컬 TCP RST 설정 실패");
        }
    }
}

/// 한쪽 FIN 뒤에도 반대 방향 응답을 계속 전달한다. 오류·취소는 로컬 소켓을 RST로 닫는다.
pub async fn forward_tcp(socket: TcpStream, gateway: GatewayClient, target: Target) -> Result<()> {
    let mut local = ResetOnFailure::new(socket);
    let remote = gateway.open_tcp(target).await?;
    {
        let (mut reader, mut writer) = local.socket.split();
        let outbound = async {
            let mut buffer = [0; 16384];
            loop {
                let length = reader.read(&mut buffer).await?;
                if length == 0 {
                    remote.finish().await?;
                    break;
                }
                remote.send_tcp(&buffer[..length]).await?;
            }
            Ok::<_, anyhow::Error>(())
        };
        let inbound = async {
            while let Some(bytes) = remote.receive().await? {
                writer.write_all(&bytes).await?;
            }
            writer.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(outbound, inbound)?;
    }
    local.graceful = true;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct RelayLimits {
    pub max_tcp_connections: usize,
    pub max_udp_associations: usize,
    pub udp_queue_frames: usize,
    pub udp_queue_bytes: usize,
    pub max_dns_jobs: usize,
    pub udp_idle: Duration,
    pub dns_idle: Duration,
}
impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_tcp_connections: 256,
            max_udp_associations: 1024,
            udp_queue_frames: 32,
            udp_queue_bytes: 16 * 1024 * 1024,
            max_dns_jobs: 64,
            udp_idle: Duration::from_secs(120),
            dns_idle: Duration::from_secs(30),
        }
    }
}
impl RelayLimits {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=16384).contains(&self.max_tcp_connections)
                && (1..=16384).contains(&self.max_udp_associations)
                && (1..=1024).contains(&self.udp_queue_frames),
            "릴레이 연결·큐 한도가 잘못됐습니다"
        );
        ensure!(
            (131072..=256 * 1024 * 1024).contains(&self.udp_queue_bytes)
                && (1..=1024).contains(&self.max_dns_jobs),
            "릴레이 메모리·DNS 한도가 잘못됐습니다"
        );
        ensure!(
            !self.udp_idle.is_zero()
                && !self.dns_idle.is_zero()
                && self.udp_idle <= Duration::from_secs(3600)
                && self.dns_idle <= Duration::from_secs(3600),
            "릴레이 유휴 시간이 잘못됐습니다"
        );
        Ok(())
    }
}

pub struct RelayContext {
    pub nat: Arc<NatSessionTable>,
    pub dns: Arc<DnsService>,
    pub gateways: Arc<GatewaySlot>,
    pub limits: RelayLimits,
    started: Instant,
}
impl RelayContext {
    pub fn new(
        nat: Arc<NatSessionTable>,
        dns: Arc<DnsService>,
        gateways: Arc<GatewaySlot>,
        limits: RelayLimits,
    ) -> Result<Self> {
        Self::with_started(nat, dns, gateways, limits, Instant::now())
    }
    pub fn with_started(
        nat: Arc<NatSessionTable>,
        dns: Arc<DnsService>,
        gateways: Arc<GatewaySlot>,
        limits: RelayLimits,
        started: Instant,
    ) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            nat,
            dns,
            gateways,
            limits,
            started,
        })
    }
    pub fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }
}

pub async fn serve_tcp(
    listener: TcpListener,
    context: Arc<RelayContext>,
    mut stopping: watch::Receiver<bool>,
) -> Result<()> {
    ensure!(
        listener.local_addr()?.ip().is_loopback(),
        "TCP 릴레이는 루프백에만 바인딩해야 합니다"
    );
    let permits = Arc::new(Semaphore::new(context.limits.max_tcp_connections));
    let mut tasks = JoinSet::new();
    let result = async {
        loop {
            if *stopping.borrow() { break; }
            tokio::select! {
                _ = stopping.changed() => break,
                completed = tasks.join_next(), if !tasks.is_empty() => if let Some(Err(error)) = completed { tracing::error!(%error, "TCP 릴레이 작업 중단"); },
                accepted = listener.accept() => {
                    let (socket, peer) = accepted?;
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else { drop(ResetOnFailure::new(socket)); continue; };
                    let Some(session) = context.nat.by_alias(Protocol::Tcp, peer, context.now_ms()) else { drop(ResetOnFailure::new(socket)); continue; };
                    if socket.local_addr()? != session.relay { drop(ResetOnFailure::new(socket)); continue; }
                    let context = Arc::clone(&context);
                    tasks.spawn(async move {
                        let _permit = permit;
                        let result = if session.flow.target.port() == 53 { context.dns.serve_tcp(socket, context.limits.dns_idle).await }
                        else {
                            let prepared = context.dns.resolve_target(session.flow.target).and_then(|resolved| context.gateways.current().map(|gateway| (resolved, gateway)));
                            match prepared { Ok((resolved, gateway)) => forward_tcp(socket, gateway, resolved.target().clone()).await, Err(error) => { drop(ResetOnFailure::new(socket)); Err(error) } }
                        };
                        if let Err(error) = result { tracing::debug!(pid = session.pid, %error, "TCP 릴레이 종료"); }
                    });
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}

struct Datagram {
    bytes: Vec<u8>,
    _memory: OwnedSemaphorePermit,
}
struct Association {
    generation: u64,
    sender: mpsc::Sender<Datagram>,
}
enum UdpTask {
    Dns,
    Association { peer: SocketAddr, generation: u64 },
}

async fn udp_association(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    session: NatSession,
    context: Arc<RelayContext>,
    mut input: mpsc::Receiver<Datagram>,
) -> Result<()> {
    let resolved = context.dns.resolve_target(session.flow.target)?;
    let gateway = context.gateways.current()?;
    let remote = tokio::time::timeout(
        context.limits.udp_idle,
        gateway.open_udp(resolved.target().clone()),
    )
    .await
    .context("UDP association 열기 제한 시간 초과")??;
    loop {
        let idle = tokio::time::sleep(context.limits.udp_idle);
        tokio::pin!(idle);
        tokio::select! {
            _ = &mut idle => break,
            packet = input.recv() => {
                let Some(packet) = packet else { break; };
                ensure!(context.nat.lookup(&session.flow).is_some_and(|current| current.generation == session.generation), "UDP NAT 세대가 바뀌었습니다");
                tokio::time::timeout(context.limits.udp_idle, remote.send_datagram(&packet.bytes)).await.context("UDP 송신 윈도 대기 시간 초과")??;
            }
            response = remote.receive() => {
                let Some(bytes) = response? else { break; };
                ensure!(context.nat.by_alias(Protocol::Udp, peer, context.now_ms()).is_some_and(|current| current.generation == session.generation), "종료된 UDP NAT 세션의 응답입니다");
                let sent = socket.send_to(&bytes, peer).await?; ensure!(sent == bytes.len(), "UDP 응답이 일부만 전송됐습니다");
            }
        }
    }
    Ok(())
}

pub async fn serve_udp(
    socket: UdpSocket,
    context: Arc<RelayContext>,
    mut stopping: watch::Receiver<bool>,
) -> Result<()> {
    ensure!(
        socket.local_addr()?.ip().is_loopback(),
        "UDP 릴레이는 루프백에만 바인딩해야 합니다"
    );
    let socket = Arc::new(socket);
    let budget = Arc::new(Semaphore::new(context.limits.udp_queue_bytes));
    let dns_jobs = Arc::new(Semaphore::new(context.limits.max_dns_jobs));
    let mut associations: HashMap<SocketAddr, Association> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut buffer = vec![0; 65536];
    let result = async {
        loop {
            if *stopping.borrow() { break; }
            tokio::select! {
                _ = stopping.changed() => break,
                completed = tasks.join_next(), if !tasks.is_empty() => match completed {
                    Some(Ok(UdpTask::Association { peer, generation })) => { if associations.get(&peer).is_some_and(|entry| entry.generation == generation) { associations.remove(&peer); } },
                    Some(Err(error)) => tracing::error!(%error, "UDP 릴레이 작업 중단"), _ => (),
                },
                received = socket.recv_from(&mut buffer) => {
                    let (length, peer) = received?; if length > MAX_DATAGRAM { continue; }
                    let Some(session) = context.nat.by_alias(Protocol::Udp, peer, context.now_ms()) else { continue; };
                    if socket.local_addr()? != session.relay { continue; }
                    let Ok(memory) = Arc::clone(&budget).try_acquire_many_owned((length + 128) as u32) else { continue; };
                    let packet = Datagram { bytes: buffer[..length].to_vec(), _memory: memory };
                    if session.flow.target.port() == 53 {
                        let Ok(permit) = Arc::clone(&dns_jobs).try_acquire_owned() else { continue; };
                        let socket = Arc::clone(&socket); let context = Arc::clone(&context);
                        tasks.spawn(async move {
                            let _permit = permit;
                            let result = context.dns.answer(packet.bytes).await;
                            if let Ok(response) = result
                                && context.nat.by_alias(Protocol::Udp, peer, context.now_ms()).is_some_and(|current| current.generation == session.generation)
                                    && let Err(error) = socket.send_to(&response, peer).await { tracing::debug!(%error, "UDP DNS 응답 실패"); }
                            UdpTask::Dns
                        });
                        continue;
                    }
                    if associations.get(&peer).is_some_and(|entry| entry.generation != session.generation || entry.sender.is_closed()) { associations.remove(&peer); }
                    if !associations.contains_key(&peer) {
                        if associations.len() >= context.limits.max_udp_associations { continue; }
                        let (sender, receiver) = mpsc::channel(context.limits.udp_queue_frames);
                        let generation = session.generation; let socket = Arc::clone(&socket); let context = Arc::clone(&context);
                        tasks.spawn(async move {
                            if let Err(error) = udp_association(socket, peer, session, context, receiver).await { tracing::debug!(%error, "UDP association 종료"); }
                            UdpTask::Association { peer, generation }
                        });
                        associations.insert(peer, Association { generation, sender });
                    }
                    if let Some(entry) = associations.get(&peer) { let _ = entry.sender.try_send(packet); }
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    associations.clear();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}

struct ManagerGuard {
    slot: Arc<GatewaySlot>,
    status: Arc<TunnelStatus>,
}
impl Drop for ManagerGuard {
    fn drop(&mut self) {
        self.slot.clear("게이트웨이 관리자가 종료됐습니다");
        self.status.set(TunnelState::Down);
    }
}

pub async fn manage_gateway(
    server: ServerConfig,
    security: SecurityConfig,
    paths: Arc<AppPaths>,
    slot: Arc<GatewaySlot>,
    status: Arc<TunnelStatus>,
    mut stopping: watch::Receiver<bool>,
) -> Result<()> {
    server.validate()?;
    server.endpoint_ip()?;
    security.tls_config(&paths)?;
    let _guard = ManagerGuard {
        slot: Arc::clone(&slot),
        status: Arc::clone(&status),
    };
    let mut attempt = 0u32;
    loop {
        if *stopping.borrow() {
            return Ok(());
        }
        slot.clear("터널을 다시 연결합니다");
        status.set(TunnelState::Reconnecting);
        let connecting = GatewayClient::connect(
            &server,
            &security,
            &paths,
            Arc::clone(&status),
            GatewayLimits::default(),
        );
        let result = tokio::select! { _ = stopping.changed() => return Ok(()), result = connecting => result };
        match result {
            Ok(client) => {
                attempt = 0;
                slot.install(client.clone())?;
                tracing::info!("게이트웨이 연결과 상호 인증 완료");
                tokio::select! { _ = stopping.changed() => return Ok(()), _ = client.closed() => () }
            }
            Err(error) => tracing::warn!(%error, "게이트웨이 연결 실패"),
        }
        slot.clear("연결이 끊겼습니다");
        status.set(TunnelState::Reconnecting);
        let delay = Duration::from_millis(
            (500u64.saturating_mul(1u64 << attempt.min(6))).min(30000)
                + u64::from(rand::random::<u16>() % 250),
        );
        attempt = attempt.saturating_add(1);
        tokio::select! { _ = stopping.changed() => return Ok(()), _ = tokio::time::sleep(delay) => () }
    }
}
