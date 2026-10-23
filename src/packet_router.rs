//! 소유권·연결 상태·NAT·인터페이스 복원을 한 결정 경로로 묶는다.
//! 소유권을 확인하지 못한 송신 패킷은 재시도 대상으로 반환하며 직접 통과시키지 않는다.

use crate::{
    nat_engine::{self, FlowKey, KillSwitchAction, NatSessionTable, TunnelStatus},
    packet,
    process_tracker::{ActiveSocketTable, ProcessIdentity, SocketOwnership},
};
use anyhow::{Result, ensure};
use dashmap::DashMap;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetworkPath {
    pub interface: u32,
    pub sub_interface: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    Malformed,
    AmbiguousOwner,
    StaleOwner,
    StateUnavailable,
    NatFailure,
    MissingReturnPath,
    TunnelUnavailable,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Pass,
    AwaitOwnership,
    Drop(DropReason),
    Inject {
        packet: Vec<u8>,
        outbound: bool,
        path: NetworkPath,
    },
}

#[derive(Clone, Copy)]
struct ProcessState {
    creation_time: u64,
    tracked: bool,
}
#[derive(Clone, Copy)]
struct ReturnPath {
    generation: u64,
    creation_time: u64,
    network: NetworkPath,
    loopback: bool,
}

pub struct PacketRouter {
    pub nat: Arc<NatSessionTable>,
    pub sockets: Arc<ActiveSocketTable>,
    pub status: Arc<TunnelStatus>,
    processes: RwLock<HashMap<u32, ProcessState>>,
    excluded: HashSet<u32>,
    paths: DashMap<FlowKey, ReturnPath>,
}

impl PacketRouter {
    pub fn new(
        nat: Arc<NatSessionTable>,
        sockets: Arc<ActiveSocketTable>,
        status: Arc<TunnelStatus>,
        excluded: impl IntoIterator<Item = u32>,
    ) -> Self {
        Self {
            nat,
            sockets,
            status,
            processes: RwLock::new(HashMap::new()),
            excluded: excluded.into_iter().collect(),
            paths: DashMap::new(),
        }
    }

    /// 프로세스 신원과 추적 여부를 같은 잠금에서 교체해 서로 다른 세대를 섞지 않는다.
    pub fn replace_processes(
        &self,
        processes: &[ProcessIdentity],
        tracked: impl IntoIterator<Item = u32>,
    ) -> Result<()> {
        let tracked: HashSet<_> = tracked.into_iter().collect();
        let replacement: HashMap<_, _> = processes
            .iter()
            .map(|process| {
                (
                    process.pid,
                    ProcessState {
                        creation_time: process.creation_time,
                        tracked: tracked.contains(&process.pid)
                            && !self.excluded.contains(&process.pid),
                    },
                )
            })
            .collect();
        ensure!(
            replacement.len() == processes.len(),
            "프로세스 스냅숏에 PID 중복이 있습니다"
        );
        ensure!(
            tracked.iter().all(|pid| replacement.contains_key(pid)),
            "추적 PID가 프로세스 스냅숏에 없습니다"
        );
        *self
            .processes
            .write()
            .map_err(|_| anyhow::anyhow!("프로세스 상태 잠금 손상"))? = replacement;
        Ok(())
    }

    pub fn decide(
        &self,
        packet: &[u8],
        outbound: bool,
        path: NetworkPath,
        now_ms: u64,
    ) -> Decision {
        let loopback = packet::parse(packet).is_ok_and(|meta| {
            meta.source.ip().is_loopback() && meta.destination.ip().is_loopback()
        });
        self.decide_captured(packet, outbound, loopback, path, now_ms)
    }

    /// 실제 캡처는 WinDivert의 Loopback 비트를 전달한다. 일반 로컬 인터페이스 주소도 포함한다.
    pub fn decide_captured(
        &self,
        packet: &[u8],
        outbound: bool,
        loopback: bool,
        path: NetworkPath,
        now_ms: u64,
    ) -> Decision {
        // 캡처 필터는 송신 TCP·UDP와 조각만 전달한다. 외부 수신 패킷은 수정하지 않는다.
        if !outbound {
            return Decision::Pass;
        }
        let Ok(meta) = packet::parse(packet) else {
            return Decision::Drop(DropReason::Malformed);
        };
        if let Some(session) = self.nat.by_alias(meta.protocol, meta.destination, now_ms)
            && meta.source == session.relay
        {
            let Some(original) = self.paths.get(&session.flow) else {
                return Decision::Drop(DropReason::MissingReturnPath);
            };
            if original.generation != session.generation {
                return Decision::Drop(DropReason::MissingReturnPath);
            }
            let Ok(processes) = self.processes.read() else {
                return Decision::Drop(DropReason::StateUnavailable);
            };
            if !processes.get(&session.pid).is_some_and(|process| {
                process.creation_time == original.creation_time && process.tracked
            }) {
                return Decision::Drop(DropReason::StaleOwner);
            }
            let mut restored = packet.to_vec();
            if packet::rewrite(&mut restored, session.flow.target, session.flow.client).is_err() {
                return Decision::Drop(DropReason::NatFailure);
            }
            return Decision::Inject {
                packet: restored,
                // Windows 루프백 패킷은 송신 경로로 복원해야 소켓에 전달된다.
                outbound: original.loopback,
                path: original.network,
            };
        }
        let (pid, creation_time) =
            match self
                .sockets
                .owner_identity(meta.protocol, meta.source, now_ms)
            {
                SocketOwnership::Unknown => return Decision::AwaitOwnership,
                SocketOwnership::Ambiguous => return Decision::Drop(DropReason::AmbiguousOwner),
                SocketOwnership::Known { pid, creation_time } => (pid, creation_time),
            };
        let tracked = {
            let Ok(processes) = self.processes.read() else {
                return Decision::Drop(DropReason::StateUnavailable);
            };
            let Some(process) = processes.get(&pid) else {
                return Decision::AwaitOwnership;
            };
            if process.creation_time != creation_time {
                return Decision::Drop(DropReason::StaleOwner);
            }
            process.tracked
        };
        if !tracked {
            return Decision::Pass;
        }
        match nat_engine::kill_switch(packet, true, self.status.get()) {
            Ok(KillSwitchAction::DropWithReply(packet)) => {
                return Decision::Inject {
                    packet,
                    outbound: loopback,
                    path,
                };
            }
            Ok(KillSwitchAction::Drop) => return Decision::Drop(DropReason::TunnelUnavailable),
            Err(_) => return Decision::Drop(DropReason::Malformed),
            Ok(KillSwitchAction::Forward) => (),
        }
        let flow = FlowKey {
            protocol: meta.protocol,
            client: meta.source,
            target: meta.destination,
        };
        if let Some(existing) = self.nat.lookup(&flow)
            && self.paths.get(&flow).is_some_and(|previous| {
                previous.generation == existing.generation
                    && previous.creation_time != creation_time
            })
        {
            return Decision::Drop(DropReason::StaleOwner);
        }
        let mut redirected = packet.to_vec();
        match self.nat.redirect(&mut redirected, pid, now_ms) {
            Ok(session) => {
                self.paths.insert(
                    flow,
                    ReturnPath {
                        generation: session.generation,
                        creation_time,
                        network: path,
                        loopback,
                    },
                );
                // 송신 주입은 IfIdx를 사용하지 않는다. 루프백 주소의 경로는 Windows가 선택한다.
                Decision::Inject {
                    packet: redirected,
                    outbound: true,
                    path: NetworkPath::default(),
                }
            }
            Err(_) => Decision::Drop(DropReason::NatFailure),
        }
    }

    pub fn evict(&self, now_ms: u64, tcp_ttl_ms: u64, udp_ttl_ms: u64) -> Result<()> {
        self.sockets.evict(now_ms)?;
        self.nat.evict(now_ms, tcp_ttl_ms, udp_ttl_ms)?;
        self.paths.retain(|flow, previous| {
            self.nat
                .lookup(flow)
                .is_some_and(|session| session.generation == previous.generation)
        });
        Ok(())
    }
}
