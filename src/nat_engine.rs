//! 전체 5-튜플과 루프백 별칭을 사용하여 UDP의 다중 목적지 충돌을 피한다.

use crate::packet::{self, PacketError, Protocol};
use dashmap::DashMap;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
};
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TunnelState {
    Down = 0,
    Reconnecting = 1,
    Connected = 2,
}

#[derive(Debug, Default)]
pub struct TunnelStatus(AtomicU8);
impl TunnelStatus {
    pub fn set(&self, value: TunnelState) {
        self.0.store(value as u8, Ordering::Release);
    }
    pub fn get(&self) -> TunnelState {
        match self.0.load(Ordering::Acquire) {
            2 => TunnelState::Connected,
            1 => TunnelState::Reconnecting,
            _ => TunnelState::Down,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub protocol: Protocol,
    pub client: SocketAddr,
    pub target: SocketAddr,
}

#[derive(Clone, Debug)]
pub struct NatSession {
    pub generation: u64,
    pub flow: FlowKey,
    pub alias: SocketAddr,
    pub relay: SocketAddr,
    pub pid: u32,
    pub created_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Debug, Error)]
pub enum NatError {
    #[error(transparent)]
    Packet(#[from] PacketError),
    #[error("NAT 세션 또는 별칭 포트 한도에 도달했습니다")]
    Capacity,
    #[error("NAT 상태 잠금이 손상됐습니다")]
    Poison,
    #[error("다른 프로세스의 기존 NAT 흐름과 충돌했습니다")]
    Ownership,
}

pub struct NatSessionTable {
    sessions: DashMap<FlowKey, NatSession>,
    aliases: DashMap<(Protocol, SocketAddr), FlowKey>,
    mutation: Mutex<u16>,
    generation: AtomicU64,
    capacity: usize,
    tcp_port: u16,
    udp_port: u16,
}

impl NatSessionTable {
    pub fn new(capacity: usize, tcp_port: u16, udp_port: u16) -> Self {
        Self {
            sessions: DashMap::new(),
            aliases: DashMap::new(),
            mutation: Mutex::new(20000),
            generation: AtomicU64::new(1),
            capacity,
            tcp_port,
            udp_port,
        }
    }
    pub fn len(&self) -> usize {
        self.sessions.len()
    }
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn register(&self, flow: FlowKey, pid: u32, now_ms: u64) -> Result<NatSession, NatError> {
        // 두 인덱스의 갱신은 하나의 쓰기 잠금으로 묶어 중간 상태의 할당을 방지한다.
        let mut next = self.mutation.lock().map_err(|_| NatError::Poison)?;
        if let Some(mut session) = self.sessions.get_mut(&flow) {
            if session.pid != pid {
                return Err(NatError::Ownership);
            }
            session.last_seen_ms = now_ms;
            return Ok(session.clone());
        }
        if self.sessions.len() >= self.capacity {
            return Err(NatError::Capacity);
        }
        for _ in 0..40000 {
            let port = *next;
            *next = if port == 59999 { 20000 } else { port + 1 };
            let ip = if flow.client.is_ipv4() {
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
            } else {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            };
            let alias = SocketAddr::new(ip, port);
            if self.aliases.contains_key(&(flow.protocol, alias)) {
                continue;
            }
            let relay_ip = if flow.client.is_ipv4() {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            };
            let relay_port = match flow.protocol {
                Protocol::Tcp => self.tcp_port,
                Protocol::Udp => self.udp_port,
            };
            if relay_port == port {
                continue;
            }
            let session = NatSession {
                generation: self
                    .generation
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                        value.checked_add(1)
                    })
                    .map_err(|_| NatError::Capacity)?,
                flow,
                alias,
                relay: SocketAddr::new(relay_ip, relay_port),
                pid,
                created_ms: now_ms,
                last_seen_ms: now_ms,
            };
            self.sessions.insert(flow, session.clone());
            self.aliases.insert((flow.protocol, alias), flow);
            return Ok(session);
        }
        Err(NatError::Capacity)
    }

    pub fn lookup(&self, flow: &FlowKey) -> Option<NatSession> {
        self.sessions.get(flow).map(|v| v.clone())
    }

    pub fn by_alias(
        &self,
        protocol: Protocol,
        alias: SocketAddr,
        now_ms: u64,
    ) -> Option<NatSession> {
        let flow = *self.aliases.get(&(protocol, alias))?;
        let mut session = self.sessions.get_mut(&flow)?;
        session.last_seen_ms = now_ms;
        Some(session.clone())
    }

    pub fn redirect(
        &self,
        packet: &mut [u8],
        pid: u32,
        now_ms: u64,
    ) -> Result<NatSession, NatError> {
        let meta = packet::parse(packet)?;
        let flow = FlowKey {
            protocol: meta.protocol,
            client: meta.source,
            target: meta.destination,
        };
        let session = self.register(flow, pid, now_ms)?;
        packet::rewrite(packet, session.alias, session.relay)?;
        Ok(session)
    }

    pub fn restore(&self, packet: &mut [u8], now_ms: u64) -> Result<bool, NatError> {
        let meta = packet::parse(packet)?;
        let Some(session) = self.by_alias(meta.protocol, meta.destination, now_ms) else {
            return Ok(false);
        };
        if meta.source != session.relay {
            return Ok(false);
        }
        packet::rewrite(packet, session.flow.target, session.flow.client)?;
        Ok(true)
    }

    pub fn evict(&self, now_ms: u64, tcp_ttl_ms: u64, udp_ttl_ms: u64) -> Result<usize, NatError> {
        let _guard = self.mutation.lock().map_err(|_| NatError::Poison)?;
        let expired: Vec<_> = self
            .sessions
            .iter()
            .filter(|session| {
                let ttl = match session.flow.protocol {
                    Protocol::Tcp => tcp_ttl_ms,
                    Protocol::Udp => udp_ttl_ms,
                };
                now_ms.saturating_sub(session.last_seen_ms) > ttl
            })
            .map(|v| *v.key())
            .collect();
        let mut removed = 0;
        for flow in expired {
            if let Some((_, session)) = self.sessions.remove_if(&flow, |_, session| {
                let ttl = match session.flow.protocol {
                    Protocol::Tcp => tcp_ttl_ms,
                    Protocol::Udp => udp_ttl_ms,
                };
                now_ms.saturating_sub(session.last_seen_ms) > ttl
            }) {
                self.aliases.remove(&(flow.protocol, session.alias));
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub fn snapshot(&self) -> Vec<NatSession> {
        self.sessions.iter().map(|v| v.clone()).collect()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum KillSwitchAction {
    Forward,
    DropWithReply(Vec<u8>),
    Drop,
}

/// 연결 상태가 불확실할 때는 직접 경로로 되돌리지 않고 원래 패킷을 폐기한다.
pub fn kill_switch(
    packet: &[u8],
    tracked: bool,
    state: TunnelState,
) -> Result<KillSwitchAction, PacketError> {
    if !tracked || state == TunnelState::Connected {
        return Ok(KillSwitchAction::Forward);
    }
    match packet::parse(packet)?.protocol {
        Protocol::Tcp => Ok(packet::tcp_reset(packet)?
            .map_or(KillSwitchAction::Drop, KillSwitchAction::DropWithReply)),
        Protocol::Udp => Ok(KillSwitchAction::DropWithReply(packet::udp_unreachable(
            packet,
        )?)),
    }
}

pub type SharedNatTable = Arc<NatSessionTable>;
