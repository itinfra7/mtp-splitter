//! 실행 파일 규칙, PID 재사용 방어, 자식 상속과 소켓 소유권을 관리한다.

use crate::{config::ProcessRule, packet::Protocol};
use anyhow::{Result, ensure};
use dashmap::DashMap;
use globset::{GlobBuilder, GlobMatcher};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Mutex,
};
use subtle::ConstantTimeEq;

pub struct CompiledRule {
    name: Option<String>,
    path: Option<GlobMatcher>,
    hash: Option<[u8; 32]>,
    pub include_children: bool,
}
impl CompiledRule {
    pub fn new(rule: ProcessRule) -> Result<Self> {
        ensure!(
            rule.exe_name.is_some() || rule.path_glob.is_some() || rule.sha256.is_some(),
            "비어 있는 프로세스 규칙입니다"
        );
        if let Some(name) = &rule.exe_name {
            ensure!(
                !name.is_empty() && !name.contains(['/', '\\']),
                "exe_name에는 파일 이름만 지정해야 합니다"
            );
        }
        let path = rule
            .path_glob
            .map(|pattern| {
                GlobBuilder::new(&pattern.replace('\\', "/"))
                    .case_insensitive(true)
                    .literal_separator(true)
                    .backslash_escape(false)
                    .build()
                    .map(|g| g.compile_matcher())
            })
            .transpose()?;
        let hash = rule
            .sha256
            .map(|hash| -> Result<[u8; 32]> {
                let decoded = hex::decode(hash)?;
                ensure!(decoded.len() == 32, "SHA-256은 32바이트여야 합니다");
                Ok(decoded.try_into().expect("검증한 해시 길이"))
            })
            .transpose()?;
        Ok(Self {
            name: rule.exe_name.map(|v| v.to_lowercase()),
            path,
            hash,
            include_children: rule.include_children,
        })
    }

    pub fn matches(&self, image: &Path) -> Result<bool> {
        let path = image.to_string_lossy().replace('\\', "/");
        let path = path.strip_prefix("//?/").unwrap_or(&path);
        let name = path.rsplit('/').next().unwrap_or("").to_lowercase();
        if self.name.as_ref().is_some_and(|expected| expected != &name)
            || self
                .path
                .as_ref()
                .is_some_and(|pattern| !pattern.is_match(path))
        {
            return Ok(false);
        }
        if let Some(expected) = self.hash {
            let mut file = File::open(image)?;
            let mut hasher = Sha256::new();
            let mut buffer = [0; 65536];
            loop {
                let size = file.read(&mut buffer)?;
                if size == 0 {
                    break;
                }
                hasher.update(&buffer[..size]);
            }
            let hash: [u8; 32] = hasher.finalize().into();
            if hash.ct_eq(&expected).unwrap_u8() != 1 {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub parent: u32,
    pub creation_time: u64,
    pub image: PathBuf,
}
#[derive(Clone, Debug)]
pub struct TrackedProcess {
    pub identity: ProcessIdentity,
    pub inherit: bool,
}

pub struct ProcessTracker {
    rules: Vec<CompiledRule>,
    tracked: HashMap<u32, TrackedProcess>,
    excluded: HashSet<u32>,
    evaluated: HashMap<u32, (ProcessIdentity, bool, bool)>,
}
impl ProcessTracker {
    pub fn new(rules: Vec<ProcessRule>, excluded: impl IntoIterator<Item = u32>) -> Result<Self> {
        let rules = rules
            .into_iter()
            .map(CompiledRule::new)
            .collect::<Result<Vec<_>>>()?;
        ensure!(!rules.is_empty(), "프로세스 규칙이 없습니다");
        Ok(Self {
            rules,
            tracked: HashMap::new(),
            excluded: excluded.into_iter().collect(),
            evaluated: HashMap::new(),
        })
    }

    pub fn refresh(&mut self, processes: &[ProcessIdentity]) -> Result<()> {
        let current: HashMap<_, _> = processes.iter().map(|p| (p.pid, p)).collect();
        ensure!(
            current.len() == processes.len(),
            "프로세스 스냅숏에 PID 중복이 있습니다"
        );
        // SHA-256 규칙을 포함한 판정은 같은 실행 신원에 한 번만 수행한다.
        // PID·생성 시각·이미지가 바뀌면 음성 판정도 버려 새 이미지를 검사한다.
        self.evaluated.retain(|pid, (identity, _, _)| {
            current.get(pid).is_some_and(|process| *process == identity)
        });
        // 직전 관찰 뒤 부모가 종료돼도 그 사이 태어나 살아 있는 자식의 상속은 이어 간다.
        // 같은 PID의 새 부모가 현재 존재하면 과거 부모의 정책을 대신 적용하지 않는다.
        let previous_parents: HashMap<_, _> = self
            .tracked
            .iter()
            .filter(|(_, process)| process.inherit)
            .map(|(pid, process)| (*pid, process.identity.creation_time))
            .collect();
        self.tracked.retain(|pid, tracked| {
            current.get(pid).is_some_and(|p| {
                p.creation_time == tracked.identity.creation_time
                    && p.image == tracked.identity.image
            })
        });
        for process in processes {
            if self.excluded.contains(&process.pid) || self.tracked.contains_key(&process.pid) {
                continue;
            }
            let (matched, inherit) =
                if let Some((_, matched, inherit)) = self.evaluated.get(&process.pid) {
                    (*matched, *inherit)
                } else {
                    let mut matched = false;
                    let mut inherit = false;
                    for rule in &self.rules {
                        if rule.matches(&process.image)? {
                            matched = true;
                            inherit |= rule.include_children;
                        }
                    }
                    self.evaluated
                        .insert(process.pid, (process.clone(), matched, inherit));
                    (matched, inherit)
                };
            if matched {
                self.tracked.insert(
                    process.pid,
                    TrackedProcess {
                        identity: process.clone(),
                        inherit,
                    },
                );
            }
        }
        // 스냅숏 열거 순서와 무관하게 여러 세대의 자손을 고정점까지 전파한다.
        for _ in 0..processes.len() {
            let mut changed = false;
            for process in processes {
                if self.excluded.contains(&process.pid) || self.tracked.contains_key(&process.pid) {
                    continue;
                }
                let live_parent = self.tracked.get(&process.parent).is_some_and(|p| {
                    p.inherit && p.identity.creation_time <= process.creation_time
                });
                let exited_parent = !current.contains_key(&process.parent)
                    && previous_parents
                        .get(&process.parent)
                        .is_some_and(|creation_time| *creation_time <= process.creation_time);
                if live_parent || exited_parent {
                    self.tracked.insert(
                        process.pid,
                        TrackedProcess {
                            identity: process.clone(),
                            inherit: true,
                        },
                    );
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        Ok(())
    }
    pub fn get(&self, pid: u32) -> Option<&TrackedProcess> {
        self.tracked.get(&pid)
    }
    pub fn tracked(&self) -> impl Iterator<Item = &TrackedProcess> {
        self.tracked.values()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SocketKey {
    pub protocol: Protocol,
    pub local: SocketAddr,
}
#[derive(Clone, Copy, Debug)]
pub struct SocketOwner {
    pub endpoint_id: u64,
    pub pid: u32,
    pub creation_time: u64,
    pub close_after_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
pub struct SocketBinding {
    pub key: SocketKey,
    pub pid: u32,
    pub creation_time: u64,
}

#[derive(Default)]
struct SocketSnapshot {
    expires_ms: u64,
    entries: HashMap<SocketKey, Vec<(u32, u64)>>,
}

#[derive(Default)]
pub struct ActiveSocketTable {
    sockets: DashMap<SocketKey, Vec<SocketOwner>>,
    endpoints: DashMap<u64, SocketKey>,
    mutation: Mutex<SocketSnapshot>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ownership {
    Unknown,
    Known(u32),
    Ambiguous,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketOwnership {
    Unknown,
    Known { pid: u32, creation_time: u64 },
    Ambiguous,
}

impl ActiveSocketTable {
    /// IP Helper의 소유권은 별도 세대로 교체한다. 커널 엔드포인트 ID를 임의로 만들지 않는다.
    pub fn replace_snapshot(
        &self,
        bindings: &[SocketBinding],
        now_ms: u64,
        valid_for_ms: u64,
    ) -> Result<()> {
        ensure!(
            (1..=5000).contains(&valid_for_ms),
            "소켓 스냅숏 유효 시간이 잘못됐습니다"
        );
        let mut entries = HashMap::<SocketKey, Vec<(u32, u64)>>::new();
        for binding in bindings {
            ensure!(
                binding.pid != 0 && binding.key.local.port() != 0,
                "잘못된 소켓 스냅숏 행입니다"
            );
            let owners = entries.entry(binding.key).or_default();
            let identity = (binding.pid, binding.creation_time);
            if !owners.contains(&identity) {
                owners.push(identity);
            }
        }
        let mut guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("소켓 이벤트 잠금이 손상됐습니다"))?;
        *guard = SocketSnapshot {
            expires_ms: now_ms.saturating_add(valid_for_ms),
            entries,
        };
        Ok(())
    }
    pub fn register(&self, key: SocketKey, owner: SocketOwner) -> Result<()> {
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("소켓 이벤트 잠금이 손상됐습니다"))?;
        // 엔드포인트의 임시 포트가 CONNECT에서 확정되면 이전 BIND 키를 제거한다.
        if let Some(old) = self.endpoints.insert(owner.endpoint_id, key)
            && old != key
            && let Some(mut owners) = self.sockets.get_mut(&old)
        {
            owners.retain(|v| v.endpoint_id != owner.endpoint_id);
        }
        let mut owners = self.sockets.entry(key).or_default();
        owners.retain(|v| v.endpoint_id != owner.endpoint_id);
        owners.push(owner);
        Ok(())
    }
    pub fn close(&self, endpoint: u64, now_ms: u64) -> Result<()> {
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("소켓 이벤트 잠금이 손상됐습니다"))?;
        let key = self.endpoints.get(&endpoint).map(|key| *key);
        if let Some(key) = key
            && let Some(mut owners) = self.sockets.get_mut(&key)
        {
            for owner in owners.iter_mut().filter(|v| v.endpoint_id == endpoint) {
                owner.close_after_ms = Some(now_ms.saturating_add(2000));
            }
        }
        Ok(())
    }
    pub fn owner(&self, protocol: Protocol, local: SocketAddr, now_ms: u64) -> Ownership {
        match self.owner_identity(protocol, local, now_ms) {
            SocketOwnership::Unknown => Ownership::Unknown,
            SocketOwnership::Known { pid, .. } => Ownership::Known(pid),
            SocketOwnership::Ambiguous => Ownership::Ambiguous,
        }
    }
    pub fn owner_identity(
        &self,
        protocol: Protocol,
        local: SocketAddr,
        now_ms: u64,
    ) -> SocketOwnership {
        self.lookup_identity(protocol, local, now_ms, true)
    }
    /// 스냅숏 보완 없이 실제 SOCKET 이벤트로 확인한 소유권만 반환한다.
    pub fn event_owner_identity(
        &self,
        protocol: Protocol,
        local: SocketAddr,
        now_ms: u64,
    ) -> SocketOwnership {
        self.lookup_identity(protocol, local, now_ms, false)
    }
    fn lookup_identity(
        &self,
        protocol: Protocol,
        local: SocketAddr,
        now_ms: u64,
        include_snapshot: bool,
    ) -> SocketOwnership {
        // 다중 인덱스 변경 중간을 읽지 않는다. 잠금 손상은 소유권 불명으로 통과시키지 않는다.
        let Ok(guard) = self.mutation.lock() else {
            return SocketOwnership::Ambiguous;
        };
        let unspecified = match local.ip() {
            IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        };
        let keys = [
            SocketKey { protocol, local },
            SocketKey {
                protocol,
                local: SocketAddr::new(unspecified, local.port()),
            },
        ];
        let mut found = None;
        for key in keys {
            if let Some(owners) = self.sockets.get(&key) {
                for owner in owners
                    .iter()
                    .filter(|o| o.close_after_ms.is_none_or(|expiry| expiry > now_ms))
                {
                    let identity = (owner.pid, owner.creation_time);
                    match found {
                        Some(previous) if previous != identity => {
                            return SocketOwnership::Ambiguous;
                        }
                        _ => found = Some(identity),
                    }
                }
            }
            if include_snapshot
                && now_ms < guard.expires_ms
                && let Some(owners) = guard.entries.get(&key)
            {
                for identity in owners {
                    match found {
                        Some(previous) if previous != *identity => {
                            return SocketOwnership::Ambiguous;
                        }
                        _ => found = Some(*identity),
                    }
                }
            }
        }
        found.map_or(SocketOwnership::Unknown, |(pid, creation_time)| {
            SocketOwnership::Known { pid, creation_time }
        })
    }
    pub fn evict(&self, now_ms: u64) -> Result<()> {
        let mut guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("소켓 이벤트 잠금이 손상됐습니다"))?;
        if now_ms >= guard.expires_ms {
            guard.entries.clear();
        }
        self.sockets.retain(|_, owners| {
            owners.retain(|owner| {
                let keep = owner.close_after_ms.is_none_or(|expiry| expiry > now_ms);
                if !keep {
                    self.endpoints.remove(&owner.endpoint_id);
                }
                keep
            });
            !owners.is_empty()
        });
        Ok(())
    }
}
