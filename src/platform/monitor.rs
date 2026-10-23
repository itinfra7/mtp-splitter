//! SOCKET 관찰과 주기적 프로세스·IP Helper 스냅숏을 패킷 소유권 표에 연결한다.
//! 감시 오류는 연결 상태를 Down으로 내리고 호출자에게 전달하며 패킷을 직접 우회시키지 않는다.

use super::{
    divert::{DivertApi, DivertHandle, decode_ip},
    processes, socket_snapshot,
};
use crate::{
    config::ProcessRule,
    nat_engine::TunnelState,
    packet::Protocol,
    packet_router::PacketRouter,
    process_tracker::{ProcessTracker, SocketBinding, SocketKey, SocketOwner},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};

const POLL_INTERVAL: Duration = Duration::from_millis(200);
const SNAPSHOT_LIFETIME_MS: u64 = 1000;
const START_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Default)]
pub struct MonitorSnapshot {
    pub processes: usize,
    pub tracked_pids: Vec<u32>,
    pub socket_bindings: usize,
    pub refreshed_ms: u64,
}

#[derive(Default)]
pub struct MonitorCounters {
    pub socket_events: AtomicU64,
    pub unresolved_events: AtomicU64,
    pub stale_events: AtomicU64,
}

struct State {
    stopped: AtomicBool,
    failure: Mutex<Option<String>>,
    snapshot: Mutex<MonitorSnapshot>,
    router: Arc<PacketRouter>,
    started: Instant,
    counters: Arc<MonitorCounters>,
}
impl State {
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
    }
    fn failed(&self, error: anyhow::Error) {
        self.router.status.set(TunnelState::Down);
        *self.failure.lock().unwrap_or_else(|e| e.into_inner()) = Some(format!("{error:#}"));
        self.stopped.store(true, Ordering::Release);
    }
}

pub struct ProcessMonitor {
    observer: Arc<DivertHandle>,
    state: Arc<State>,
    workers: Vec<JoinHandle<()>>,
    pub counters: Arc<MonitorCounters>,
}

impl ProcessMonitor {
    pub fn start(
        api: &Arc<DivertApi>,
        router: Arc<PacketRouter>,
        rules: Vec<ProcessRule>,
        excluded: impl IntoIterator<Item = u32>,
        started: Instant,
    ) -> Result<Self> {
        let tracker = ProcessTracker::new(rules, excluded)?;
        let observer = Arc::new(DivertHandle::observe_sockets(api)?);
        let counters = Arc::new(MonitorCounters::default());
        let state = Arc::new(State {
            stopped: AtomicBool::new(false),
            failure: Mutex::new(None),
            snapshot: Mutex::new(MonitorSnapshot::default()),
            router,
            started,
            counters: Arc::clone(&counters),
        });
        let capture_state = Arc::clone(&state);
        let capture_observer = Arc::clone(&observer);
        let capture = thread::Builder::new()
            .name("mtp-socket-monitor".into())
            .spawn(move || {
                if let Err(error) = socket_events(&capture_observer, &capture_state)
                    && !capture_state.stopped.load(Ordering::Acquire)
                {
                    capture_state.failed(error);
                }
            })?;
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let poll_state = Arc::clone(&state);
        let polling = thread::Builder::new()
            .name("mtp-process-monitor".into())
            .spawn(move || {
                let mut tracker = tracker;
                let mut first = true;
                // 이전 신원 표가 교체될 때까지 프로세스 객체를 보유해 PID 재사용 창을 닫는다.
                let mut retained = None;
                while !poll_state.stopped.load(Ordering::Acquire) {
                    match refresh(&poll_state, &mut tracker) {
                        Ok(replacement) => {
                            retained.replace(replacement);
                        }
                        Err(error) => {
                            let message = format!("{error:#}");
                            poll_state.failed(error);
                            if first {
                                let _ = ready_sender.send(Err(message));
                            }
                            break;
                        }
                    }
                    if first {
                        let _ = ready_sender.send(Ok(()));
                        first = false;
                    }
                    let deadline = Instant::now() + POLL_INTERVAL;
                    while !poll_state.stopped.load(Ordering::Acquire) && Instant::now() < deadline {
                        thread::sleep(Duration::from_millis(10));
                    }
                }
            });
        let polling = match polling {
            Ok(worker) => worker,
            Err(error) => {
                state.stopped.store(true, Ordering::Release);
                let _ = observer.shutdown();
                let _ = capture.join();
                return Err(error.into());
            }
        };
        let monitor = Self {
            observer,
            state,
            workers: vec![capture, polling],
            counters,
        };
        match ready_receiver
            .recv_timeout(START_TIMEOUT)
            .context("프로세스 감시 초기화 시간 초과 또는 작업 중단")?
        {
            Ok(()) => {
                monitor.healthy()?;
                Ok(monitor)
            }
            Err(message) => anyhow::bail!("프로세스 감시 초기화 실패: {message}"),
        }
    }

    pub fn snapshot(&self) -> Result<MonitorSnapshot> {
        self.state
            .snapshot
            .lock()
            .map(|value| value.clone())
            .map_err(|_| anyhow::anyhow!("감시 스냅숏 잠금 손상"))
    }
    pub fn healthy(&self) -> Result<()> {
        let failure = self
            .state
            .failure
            .lock()
            .map_err(|_| anyhow::anyhow!("감시 오류 잠금 손상"))?;
        ensure!(
            failure.is_none(),
            "프로세스 감시 실패: {}",
            failure.as_deref().unwrap_or("알 수 없는 오류")
        );
        ensure!(
            !self.workers.iter().any(JoinHandle::is_finished),
            "프로세스 감시 작업이 중단됐습니다"
        );
        ensure!(
            self.state
                .now_ms()
                .saturating_sub(self.snapshot()?.refreshed_ms)
                <= 3000,
            "프로세스 감시 스냅숏이 3초 이상 갱신되지 않았습니다"
        );
        Ok(())
    }
}

impl Drop for ProcessMonitor {
    fn drop(&mut self) {
        self.state.stopped.store(true, Ordering::Release);
        let _ = self.observer.shutdown();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn refresh(state: &State, tracker: &mut ProcessTracker) -> Result<Vec<processes::ObservedProcess>> {
    let observed = processes::snapshot_observed()?;
    let processes: Vec<_> = observed
        .iter()
        .map(|process| process.identity.clone())
        .collect();
    ensure!(processes.len() <= 100000, "프로세스 스냅숏 한도 초과");
    tracker.refresh(&processes)?;
    let identities: HashMap<_, _> = processes
        .iter()
        .map(|process| (process.pid, process.creation_time))
        .collect();
    let sockets = socket_snapshot::snapshot()?;
    let bindings: Vec<_> = sockets
        .into_iter()
        .filter_map(|socket| {
            identities
                .get(&socket.pid)
                .map(|creation_time| SocketBinding {
                    key: socket.key,
                    pid: socket.pid,
                    creation_time: *creation_time,
                })
        })
        .collect();
    let tracked_pids: Vec<_> = tracker
        .tracked()
        .map(|process| process.identity.pid)
        .collect();
    // 신원 표를 먼저 교체한다. 소켓 표의 이전 세대가 잠깐 남으면 신원 불일치로 차단된다.
    state
        .router
        .replace_processes(&processes, tracked_pids.iter().copied())?;
    let now_ms = state.now_ms();
    state
        .router
        .sockets
        .replace_snapshot(&bindings, now_ms, SNAPSHOT_LIFETIME_MS)?;
    state.router.sockets.evict(now_ms)?;
    *state
        .snapshot
        .lock()
        .map_err(|_| anyhow::anyhow!("감시 스냅숏 잠금 손상"))? = MonitorSnapshot {
        processes: processes.len(),
        tracked_pids,
        socket_bindings: bindings.len(),
        refreshed_ms: now_ms,
    };
    Ok(observed)
}

fn filetime_now() -> Result<i128> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(i128::from(duration.as_secs()) * 10_000_000
        + i128::from(duration.subsec_nanos() / 100)
        + 116444736000000000)
}

/// 과거 이벤트를 이미 재사용된 PID의 새 프로세스에 붙이지 않도록 시간 하한을 확인한다.
fn event_after_creation(timestamp: i64, creation_time: u64, frequency: i64) -> Result<bool> {
    let before = filetime_now()?;
    let mut current = 0;
    ensure!(
        unsafe { QueryPerformanceCounter(&mut current) } != 0,
        "성능 카운터 조회 실패"
    );
    let after = filetime_now()?;
    ensure!(
        after >= before && after - before <= 10_000_000,
        "이벤트 신원 검사 중 시스템 시각이 불안정합니다"
    );
    if timestamp < 0 || timestamp > current {
        return Ok(false);
    }
    let delta = i128::from(timestamp - current) * 10_000_000 / i128::from(frequency);
    // 생성 직후 2ms 안의 경계는 확정하지 않는다. IP Helper의 다음 스냅숏으로 다시 확인한다.
    Ok(i128::from(creation_time) <= before + delta - 20_000)
}

fn socket_events(observer: &DivertHandle, state: &State) -> Result<()> {
    let mut frequency = 0;
    ensure!(
        unsafe { QueryPerformanceFrequency(&mut frequency) } != 0 && frequency > 0,
        "성능 카운터 주파수 조회 실패"
    );
    while !state.stopped.load(Ordering::Acquire) {
        let (_, address) = observer.receive(&mut [])?;
        let socket = address.socket()?;
        state.counters.socket_events.fetch_add(1, Ordering::Relaxed);
        if address.event() == 7 {
            state
                .router
                .sockets
                .close(socket.endpoint_id, state.now_ms())?;
            continue;
        }
        if !matches!(address.event(), 3..=6) || socket.local_port == 0 {
            continue;
        }
        let Ok(protocol) = Protocol::try_from(socket.protocol) else {
            continue;
        };
        let identity = match processes::identity(socket.process_id, 0) {
            Ok(identity) => identity,
            Err(error) => {
                state
                    .counters
                    .unresolved_events
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!(pid = socket.process_id, %error, "소켓 이벤트의 신원을 확인하지 못했습니다");
                continue;
            }
        };
        if !event_after_creation(address.timestamp, identity.creation_time, frequency)? {
            state.counters.stale_events.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        state.router.sockets.register(
            SocketKey {
                protocol,
                local: SocketAddr::new(decode_ip(socket.local_addr), socket.local_port),
            },
            SocketOwner {
                endpoint_id: socket.endpoint_id,
                pid: socket.process_id,
                creation_time: identity.creation_time,
                close_after_ms: None,
            },
        )?;
    }
    Ok(())
}

/// NETWORK 핸들을 열지 않고 실제 감시 상태만 표시하는 진단 명령이다.
pub fn diagnose(
    paths: &crate::paths::AppPaths,
    rules: Vec<ProcessRule>,
    seconds: u64,
) -> Result<()> {
    let _lock = paths.lock()?;
    ensure!(
        (1..=3600).contains(&seconds),
        "감시 시간은 1~3600초여야 합니다"
    );
    let api = DivertApi::load(paths)?;
    let result = (|| -> Result<()> {
        let pid = std::process::id();
        let router = Arc::new(PacketRouter::new(
            Arc::new(crate::nat_engine::NatSessionTable::new(16384, 0, 0)),
            Arc::new(crate::process_tracker::ActiveSocketTable::default()),
            Arc::new(crate::nat_engine::TunnelStatus::default()),
            [pid],
        ));
        let monitor = ProcessMonitor::start(&api, router, rules, [pid], Instant::now())?;
        println!("프로세스·SOCKET 감시를 시작했습니다. 패킷을 전환하지 않습니다");
        for _ in 0..seconds {
            thread::sleep(Duration::from_secs(1));
            monitor.healthy()?;
            let snapshot = monitor.snapshot()?;
            println!(
                "프로세스 {}개, 추적 PID {:?}, 소켓 바인딩 {}개, 수신 이벤트 {}개",
                snapshot.processes,
                snapshot.tracked_pids,
                snapshot.socket_bindings,
                monitor.counters.socket_events.load(Ordering::Relaxed)
            );
        }
        Ok(())
    })();
    let cleanup = super::driver_service::cleanup_idle(paths, &api);
    if let Err(error) = &cleanup {
        eprintln!("감시 종료 후 드라이버 정리 실패: {error:#}");
    }
    result?;
    cleanup?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn event_time_rejects_old_event_or_future_process_identity() {
        let mut frequency = 0;
        assert_ne!(unsafe { QueryPerformanceFrequency(&mut frequency) }, 0);
        let identity = processes::identity(std::process::id(), 0).unwrap();
        let mut now = 0;
        assert_ne!(unsafe { QueryPerformanceCounter(&mut now) }, 0);
        assert!(!event_after_creation(0, identity.creation_time, frequency).unwrap());
        assert!(
            !event_after_creation(
                now,
                u64::try_from(filetime_now().unwrap() + 10_000_000).unwrap(),
                frequency
            )
            .unwrap()
        );
        assert!(!event_after_creation(i64::MAX, identity.creation_time, frequency).unwrap());
    }
}
