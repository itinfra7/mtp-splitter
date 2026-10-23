//! 감시·커널 NAT·루프백 릴레이·게이트웨이·독립 watchdog의 실행 수명을 묶는다.
//! 기본 종료는 차단을 유지하며, 사용자가 지정한 종료·해제 경로만 차단을 해제한다.

use super::{
    divert::DivertApi, driver_service, guard_lock, monitor::ProcessMonitor, network::NetworkEngine,
    watchdog_client::WatchdogConnection,
};
use crate::{
    config::{self, TunnelMode},
    fake_dns::FakeIpCache,
    nat_engine::{NatSessionTable, TunnelState, TunnelStatus},
    packet_router::PacketRouter,
    paths::AppPaths,
    process_tracker::{ActiveSocketTable, CompiledRule},
    relay::{self, DnsService, GatewaySlot, RelayContext, RelayLimits},
    shared_state::{self, SharedState},
    transport::SecurityConfig,
    watchdog::RelayPorts,
};
use anyhow::{Context, Result, ensure};
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::watch,
    task::JoinSet,
};

#[derive(Clone, Copy, Debug)]
pub struct RunOptions {
    pub tcp_port: u16,
    pub udp_port: u16,
    pub release_on_exit: bool,
}
impl Default for RunOptions {
    fn default() -> Self {
        Self {
            tcp_port: 17001,
            udp_port: 17002,
            release_on_exit: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RunOutcome {
    pub watchdog_pid: u32,
    pub released: bool,
}

#[derive(Clone, Debug)]
pub struct RuntimeSnapshot {
    pub state: TunnelState,
    pub watchdog_pid: Option<u32>,
    pub tracked_processes: usize,
    pub sessions: usize,
    pub handled_packets: u64,
    pub blocked_packets: u64,
}
impl Default for RuntimeSnapshot {
    fn default() -> Self {
        Self {
            state: TunnelState::Down,
            watchdog_pid: None,
            tracked_processes: 0,
            sessions: 0,
            handled_packets: 0,
            blocked_packets: 0,
        }
    }
}
pub type RuntimeObserver = Arc<Mutex<RuntimeSnapshot>>;
struct ObserverGuard(Option<RuntimeObserver>);
impl Drop for ObserverGuard {
    fn drop(&mut self) {
        if let Some(observer) = &self.0 {
            observer.lock().unwrap_or_else(|e| e.into_inner()).state = TunnelState::Down;
        }
    }
}

fn tcp_listener(ip: IpAddr, port: u16) -> Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(SocketAddr::new(ip, port)),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    if ip.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::new(ip, port).into())?;
    socket.listen(256)?;
    Ok(TcpListener::from_std(socket.into())?)
}
fn udp_socket(ip: IpAddr, port: u16) -> Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(SocketAddr::new(ip, port)),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if ip.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::new(ip, port).into())?;
    Ok(UdpSocket::from_std(socket.into())?)
}

/// 종료 신호를 주입할 수 있어 실제 커널 통합 시험도 운영 실행 경로를 공유한다.
pub async fn run_until(
    paths: Arc<AppPaths>,
    options: RunOptions,
    shutdown: impl Future<Output = Result<()>>,
) -> Result<RunOutcome> {
    run_observed(paths, options, shutdown, None).await
}

/// GUI는 이 메모리 스냅숏만 관찰하며 암호키나 패킷 본문을 화면 상태로 복사하지 않는다.
pub async fn run_observed(
    paths: Arc<AppPaths>,
    options: RunOptions,
    shutdown: impl Future<Output = Result<()>>,
    observer: Option<RuntimeObserver>,
) -> Result<RunOutcome> {
    let _observer_guard = ObserverGuard(observer.clone());
    let _instance = paths.lock()?;
    // 남은 감시기가 보호 중인 공유 NAT 파일을 초기화하기 전에 검사한다.
    drop(guard_lock::root_lock(&paths)?);
    let (server, rules) = config::load(&paths)?;
    server.endpoint_ip()?;
    ensure!(
        server.tunnel_mode == TunnelMode::ExtendedSocksOverMtproto,
        "run은 확장 게이트웨이 모드만 지원합니다. standard_dc의 앱 릴레이는 아직 통합되지 않았습니다"
    );
    for rule in rules.iter().cloned() {
        CompiledRule::new(rule)?;
    }
    let security = SecurityConfig::load(&paths)?;
    security.tls_config(&paths)?;
    let ipv4 = "127.0.0.1".parse()?;
    let ipv6 = "::1".parse()?;
    let tcp4 = tcp_listener(ipv4, options.tcp_port).context("IPv4 TCP 릴레이 바인딩 실패")?;
    let tcp_port = tcp4.local_addr()?.port();
    let tcp6 = tcp_listener(ipv6, tcp_port).context("IPv6 TCP 릴레이 바인딩 실패")?;
    let udp4 = udp_socket(ipv4, options.udp_port).context("IPv4 UDP 릴레이 바인딩 실패")?;
    let udp_port = udp4.local_addr()?.port();
    let udp6 = udp_socket(ipv6, udp_port).context("IPv6 UDP 릴레이 바인딩 실패")?;
    let started = Instant::now();
    let status = Arc::new(TunnelStatus::default());
    let nat = Arc::new(NatSessionTable::new(
        shared_state::MAX_SESSIONS,
        tcp_port,
        udp_port,
    ));
    let slot = Arc::new(GatewaySlot::default());
    let cache = Arc::new(Mutex::new(FakeIpCache::load(
        &paths,
        NonZeroUsize::new(8192).unwrap(),
    )?));
    let dns = Arc::new(DnsService::new(
        cache,
        Arc::clone(&paths),
        Arc::clone(&slot),
    ));
    let context = Arc::new(RelayContext::with_started(
        Arc::clone(&nat),
        dns,
        Arc::clone(&slot),
        RelayLimits::default(),
        started,
    )?);
    let mut shared = SharedState::open(&paths, true)?;
    shared.publish(&[], TunnelState::Down, 0)?;
    let mut watchdog = WatchdogConnection::start(
        &paths,
        RelayPorts {
            tcp: tcp_port,
            udp: udp_port,
        },
    )
    .await?;
    let watchdog_pid = watchdog.pid();
    if let Some(observer) = &observer {
        observer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .watchdog_pid = Some(watchdog_pid);
    }
    tracing::info!(
        watchdog_pid,
        tcp_port,
        udp_port,
        "독립 차단 감시가 준비됐습니다"
    );
    println!("watchdog PID={watchdog_pid}, TCP 릴레이={tcp_port}, UDP 릴레이={udp_port}");
    println!(
        "기본 종료 뒤에도 차단을 유지합니다. 해제: mtp-splitter.exe release --watchdog-pid {watchdog_pid}"
    );
    let api = DivertApi::load(&paths)?;
    let excluded = [std::process::id(), watchdog_pid];
    let router = Arc::new(PacketRouter::new(
        Arc::clone(&nat),
        Arc::new(ActiveSocketTable::default()),
        Arc::clone(&status),
        excluded,
    ));
    let monitor = ProcessMonitor::start(&api, Arc::clone(&router), rules, excluded, started)
        .with_context(|| {
            format!("메인 프로세스 감시 시작 실패. watchdog PID {watchdog_pid}의 차단은 유지됩니다")
        })?;
    let network = NetworkEngine::start(
        &api,
        Arc::clone(&router),
        "outbound and (tcp or udp or fragment)",
        started,
    )
    .with_context(|| {
        format!("메인 패킷 감시 시작 실패. watchdog PID {watchdog_pid}의 차단은 유지됩니다")
    })?;
    let (stop, stopping) = watch::channel(false);
    let mut tasks = JoinSet::new();
    tasks.spawn(relay::serve_tcp(
        tcp4,
        Arc::clone(&context),
        stopping.clone(),
    ));
    tasks.spawn(relay::serve_tcp(
        tcp6,
        Arc::clone(&context),
        stopping.clone(),
    ));
    tasks.spawn(relay::serve_udp(
        udp4,
        Arc::clone(&context),
        stopping.clone(),
    ));
    tasks.spawn(relay::serve_udp(
        udp6,
        Arc::clone(&context),
        stopping.clone(),
    ));
    tasks.spawn(relay::manage_gateway(
        server,
        security,
        Arc::clone(&paths),
        Arc::clone(&slot),
        Arc::clone(&status),
        stopping,
    ));
    tokio::pin!(shutdown);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_heartbeat = Instant::now();
    let mut last_eviction = Instant::now();
    let mut requested = false;
    let mut external_release = false;
    let mut shutdown_finished = false;
    let mut result: Result<()> = async {
        loop {
            tokio::select! {
                signal = &mut shutdown => { shutdown_finished = true; signal?; requested = true; break; },
                completed = tasks.join_next() => {
                    if let Some(completed) = completed { completed.context("릴레이 작업이 중단됐습니다")??; }
                    anyhow::bail!("릴레이 또는 게이트웨이 관리자가 예기치 않게 종료됐습니다");
                },
                _ = tick.tick() => {
                    if watchdog.release_requested(&paths)? {
                        requested = true;
                        external_release = true;
                        break;
                    }
                    watchdog.healthy()?;
                    monitor.healthy()?;
                    network.healthy()?;
                    let now = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                    if last_eviction.elapsed() >= Duration::from_secs(1) {
                        router.evict(now, 7_200_000, 120_000)?;
                        last_eviction = Instant::now();
                    }
                    shared.publish(&nat.snapshot(), status.get(), now)?;
                    if let Some(observer) = &observer {
                        use std::sync::atomic::Ordering;
                        let mut view = observer.lock().unwrap_or_else(|e| e.into_inner());
                        view.state = status.get();
                        view.tracked_processes = monitor.snapshot()?.tracked_pids.len();
                        view.sessions = nat.len();
                        view.handled_packets = network.counters.injected.load(Ordering::Relaxed);
                        view.blocked_packets = network.counters.dropped.load(Ordering::Relaxed)
                            + network.counters.ownership_expired.load(Ordering::Relaxed)
                            + network.counters.queue_full.load(Ordering::Relaxed);
                    }
                    if last_heartbeat.elapsed() >= Duration::from_secs(1) {
                        watchdog.heartbeat().await?;
                        last_heartbeat = Instant::now();
                    }
                }
            }
        }
        Ok(())
    }.await;
    status.set(TunnelState::Down);
    slot.clear("메인 실행을 정지합니다");
    let _ = stop.send(true);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    if let Err(error) = shared.publish(
        &nat.snapshot(),
        TunnelState::Down,
        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
    ) {
        result = Err(error).context("종료 상태 게시 실패");
    }
    if watchdog.release_requested(&paths).unwrap_or_else(|error| {
        tracing::error!(%error, "명시적 해제 통지를 읽지 못했습니다");
        false
    }) {
        requested = true;
        external_release = true;
    }
    if let Err(error) = &result {
        tracing::error!(%error, watchdog_pid, "메인 실행 오류, 차단을 유지합니다");
    }
    if watchdog.healthy().is_err() && !external_release {
        // 독립 감시가 사라진 상태에서 반환하면 마지막 커널 핸들까지 닫히므로 유지한다.
        network.latch();
        tracing::error!(
            "watchdog이 종료되어 메인 커널 차단을 고정했습니다. 명시적 종료 신호를 기다립니다"
        );
        while !(external_release || requested && options.release_on_exit) {
            if watchdog.release_requested(&paths).unwrap_or(false) {
                external_release = true;
                break;
            }
            tokio::select! {
                signal = &mut shutdown, if !shutdown_finished => {
                    shutdown_finished = true;
                    match signal {
                        Ok(()) => requested = true,
                        Err(error) => tracing::error!(%error, "종료 신호 오류로 커널 차단을 유지합니다"),
                    }
                },
                _ = tokio::time::sleep(Duration::from_millis(100)) => (),
            }
        }
    }
    drop(network);
    drop(monitor);
    let released = external_release || (requested && options.release_on_exit);
    if released {
        watchdog.release(&paths).await?;
    }
    drop(shared);
    if released {
        shared_state::remove_idle(&paths)?;
        watchdog.remove_notice(&paths)?;
        driver_service::cleanup_idle(&paths, &api)?;
    } else {
        tracing::warn!(
            watchdog_pid,
            "watchdog의 차단을 남긴 채 메인 실행을 종료합니다"
        );
    }
    result?;
    Ok(RunOutcome {
        watchdog_pid,
        released,
    })
}
