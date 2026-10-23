//! 유한 큐와 소유권 대기 기한을 갖는 실제 NETWORK 캡처·변환·재주입 작업이다.
//! 작업이 실패하면 핸들을 소유한 채 수신을 중단하여 명시적 정리 전까지 차단을 유지한다.

use super::divert::{Address, DivertApi, DivertHandle};
use crate::{
    nat_engine::TunnelState,
    packet_router::{Decision, PacketRouter},
};
use anyhow::{Result, ensure};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const QUEUE_CAPACITY: usize = 256;
const OWNERSHIP_WAIT: Duration = Duration::from_millis(500);

struct Captured {
    packet: Vec<u8>,
    address: Address,
    received: Instant,
}

#[derive(Default)]
pub struct Counters {
    pub passed: AtomicU64,
    pub injected: AtomicU64,
    pub dropped: AtomicU64,
    pub ownership_expired: AtomicU64,
    pub queue_full: AtomicU64,
}

pub struct NetworkEngine {
    handle: Arc<DivertHandle>,
    _injection: Arc<DivertHandle>,
    stopped: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<String>>>,
    workers: Vec<JoinHandle<()>>,
    pub counters: Arc<Counters>,
}

impl NetworkEngine {
    pub fn start(
        api: &Arc<DivertApi>,
        router: Arc<PacketRouter>,
        filter: &str,
        started: Instant,
    ) -> Result<Self> {
        Self::start_at_priority(api, router, filter, 0, started)
    }
    pub fn start_at_priority(
        api: &Arc<DivertApi>,
        router: Arc<PacketRouter>,
        filter: &str,
        priority: i16,
        started: Instant,
    ) -> Result<Self> {
        ensure!(
            priority > -1100,
            "캡처 우선순위는 주입 전용 핸들보다 높아야 합니다"
        );
        let handle = Arc::new(api.open(filter, 0, priority, 0)?);
        // 검증·변환한 합성 패킷만 독립 차단기 아래에서 주입한다. 원본 통과는 캡처 핸들을 쓴다.
        // 특히 송신으로 복원한 루프백 응답에는 원래 원격 포트의 소유자가 존재하지 않을 수 있다.
        let injection = Arc::new(api.open("false", 0, -1100, 0x8)?);
        let stopped = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(Mutex::new(None));
        let counters = Arc::new(Counters::default());
        let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
        let capture_handle = Arc::clone(&handle);
        let capture_stopped = Arc::clone(&stopped);
        let capture_failure = Arc::clone(&failure);
        let capture_counters = Arc::clone(&counters);
        let capture_status = Arc::clone(&router.status);
        let capture = thread::Builder::new()
            .name("mtp-network-recv".into())
            .spawn(move || {
                let mut buffer = vec![0; 65575];
                while !capture_stopped.load(Ordering::Acquire) {
                    match capture_handle.receive(&mut buffer) {
                        Ok((length, address)) => {
                            let captured = Captured {
                                packet: buffer[..length].to_vec(),
                                address,
                                received: Instant::now(),
                            };
                            match sender.try_send(captured) {
                                Ok(()) => (),
                                Err(mpsc::TrySendError::Full(_)) => {
                                    capture_counters.queue_full.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(mpsc::TrySendError::Disconnected(_)) => break,
                            }
                        }
                        Err(error) if !capture_stopped.load(Ordering::Acquire) => {
                            *capture_failure.lock().unwrap_or_else(|e| e.into_inner()) =
                                Some(format!("캡처 실패: {error:#}"));
                            capture_status.set(TunnelState::Down);
                            capture_stopped.store(true, Ordering::Release);
                            break;
                        }
                        Err(_) => break,
                    }
                }
            })?;
        let process_handle = Arc::clone(&handle);
        let injection_handle = Arc::clone(&injection);
        let process_stopped = Arc::clone(&stopped);
        let process_failure = Arc::clone(&failure);
        let process_counters = Arc::clone(&counters);
        let processor = thread::Builder::new()
            .name("mtp-network-route".into())
            .spawn(move || {
                let mut pending = VecDeque::<Captured>::new();
                while !process_stopped.load(Ordering::Acquire) {
                    let timeout = if pending.is_empty() {
                        Duration::from_millis(100)
                    } else {
                        Duration::from_millis(2)
                    };
                    match receiver.recv_timeout(timeout) {
                        Ok(captured) if pending.len() < QUEUE_CAPACITY => {
                            pending.push_back(captured)
                        }
                        Ok(_) => {
                            process_counters.queue_full.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => (),
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                    let count = pending.len();
                    for _ in 0..count {
                        let Some(mut captured) = pending.pop_front() else {
                            break;
                        };
                        let now_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                        if let Ok(meta) = crate::packet::parse(&captured.packet) {
                            let flags = if meta.protocol == crate::packet::Protocol::Tcp { captured.packet[meta.transport + 13] } else { 0 };
                            tracing::trace!(source = %meta.source, destination = %meta.destination, length = meta.length, flags, outbound = captured.address.outbound(), interface = captured.address.network_path().interface, "캡처 패킷 헤더");
                        }
                        let action = router.decide_captured(
                            &captured.packet,
                            captured.address.outbound(),
                            captured.address.loopback(),
                            captured.address.network_path(),
                            now_ms,
                        );
                        let result = match action {
                            Decision::Pass => {
                                process_counters.passed.fetch_add(1, Ordering::Relaxed);
                                process_handle.send(&captured.packet, &captured.address)
                            }
                            Decision::Inject {
                                mut packet,
                                outbound,
                                path,
                            } => {
                                if let Ok(meta) = crate::packet::parse(&packet) {
                                    tracing::trace!(source = %meta.source, destination = %meta.destination, outbound, interface = path.interface, "재주입 패킷 헤더");
                                }
                                captured.address.set_outbound(outbound);
                                captured.address.set_network_path(path);
                                captured.address.bits &= !(7 << 21);
                                captured.address.bits = (captured.address.bits & !(1 << 20))
                                    | (u32::from(packet[0] >> 4 == 6) << 20);
                                injection_handle
                                    .recalculate(&mut packet, &mut captured.address)
                                    .and_then(|()| injection_handle.send(&packet, &captured.address))
                                    .map(|()| {
                                        process_counters.injected.fetch_add(1, Ordering::Relaxed);
                                    })
                            }
                            Decision::Drop(reason) => {
                                tracing::debug!(?reason, "송신 패킷 차단");
                                process_counters.dropped.fetch_add(1, Ordering::Relaxed);
                                Ok(())
                            }
                            Decision::AwaitOwnership => {
                                if captured.received.elapsed() < OWNERSHIP_WAIT {
                                    pending.push_back(captured);
                                } else {
                                    process_counters
                                        .ownership_expired
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                Ok(())
                            }
                        };
                        if let Err(error) = result {
                            *process_failure.lock().unwrap_or_else(|e| e.into_inner()) =
                                Some(format!("패킷 재주입 실패: {error:#}"));
                            router.status.set(TunnelState::Down);
                            process_stopped.store(true, Ordering::Release);
                            break;
                        }
                    }
                }
            });
        let processor = match processor {
            Ok(worker) => worker,
            Err(error) => {
                stopped.store(true, Ordering::Release);
                let _ = handle.shutdown();
                let _ = capture.join();
                return Err(error.into());
            }
        };
        Ok(Self {
            handle,
            _injection: injection,
            stopped,
            failure,
            workers: vec![capture, processor],
            counters,
        })
    }

    pub fn healthy(&self) -> Result<()> {
        let failure = self
            .failure
            .lock()
            .map_err(|_| anyhow::anyhow!("캡처 오류 상태 잠금 손상"))?;
        ensure!(
            failure.is_none(),
            "{}",
            failure.as_deref().unwrap_or("알 수 없는 캡처 오류")
        );
        ensure!(
            !self.workers.iter().any(JoinHandle::is_finished),
            "패킷 작업이 예기치 않게 종료됐습니다"
        );
        Ok(())
    }
    /// 핸들을 닫지 않고 수신·재주입을 멈춘다. 남은 커널 큐와 이후 일치 패킷은 통과하지 않는다.
    pub fn latch(&self) {
        self.stopped.store(true, Ordering::Release);
    }
}

impl Drop for NetworkEngine {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let _ = self.handle.shutdown();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}
