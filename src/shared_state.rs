//! 프로세스 간 공유 상태의 각 필드를 원자적으로 접근하는 이중 검증 스냅숏이다.
//! 단일 작성자와 다중 독자를 전제로 하며, 죽은 작성자의 홀수 세대는 읽지 않는다.

use crate::{
    nat_engine::{NatSession, TunnelState},
    paths::AppPaths,
};
use anyhow::{Result, bail, ensure};
use memmap2::{MmapMut, MmapOptions};
use std::{
    fs::{File, OpenOptions},
    sync::atomic::{AtomicU64, Ordering},
};

const MAGIC: u64 = 0x3154504c5350544d;
const HEADER_WORDS: usize = 8;
const ROW_WORDS: usize = 16;
pub const MAX_SESSIONS: usize = 16384;
const SIZE: usize = (HEADER_WORDS + ROW_WORDS * MAX_SESSIONS) * 8;

/// 인스턴스 또는 watchdog 수명 잠금을 소유한 호출자만 사용한다.
/// 메인 작성자가 살아 있으면 파일을 보존하며 Fake-IP·빌드 캐시는 지우지 않는다.
pub fn remove_idle(paths: &AppPaths) -> Result<bool> {
    let path = paths.resolve("runtime/nat_session.bin")?;
    let file = match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error.into()),
    };
    if let Err(error) = fs2::FileExt::try_lock_exclusive(&file) {
        if error.kind() == std::io::ErrorKind::WouldBlock || error.raw_os_error() == Some(33) {
            return Ok(false);
        }
        return Err(error.into());
    }
    drop(file);
    std::fs::remove_file(path)?;
    Ok(true)
}

pub struct SharedState {
    map: MmapMut,
    _file: File,
    writer: bool,
}

#[derive(Clone, Debug)]
pub struct SharedSnapshot {
    pub heartbeat_ms: u64,
    pub state: TunnelState,
    pub rows: Vec<[u64; ROW_WORDS]>,
}

impl SharedState {
    pub fn open(paths: &AppPaths, writer: bool) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        if writer {
            options.create(true);
        }
        let file = options.open(paths.resolve("runtime/nat_session.bin")?)?;
        if writer {
            fs2::FileExt::try_lock_exclusive(&file)?;
            file.set_len(SIZE as u64)?;
        }
        ensure!(
            file.metadata()?.len() == SIZE as u64,
            "공유 NAT 파일의 크기가 잘못됐습니다"
        );
        // 파일을 보유하는 동안 크기는 고정된다. 참여 프로세스는 이 모듈의 원자 연산만 사용한다.
        let map = unsafe { MmapOptions::new().len(SIZE).map_mut(&file)? };
        let this = Self {
            map,
            _file: file,
            writer,
        };
        if writer {
            this.word(0).store(MAGIC, Ordering::Release);
            this.word(1).store(0, Ordering::Release);
            this.word(2).store(0, Ordering::Release);
            this.word(3).store(0, Ordering::Release);
            this.word(4).store(0, Ordering::Release);
        } else {
            ensure!(
                this.word(0).load(Ordering::Acquire) == MAGIC,
                "공유 NAT 파일의 서명이 잘못됐습니다"
            );
        }
        Ok(this)
    }
    fn word(&self, index: usize) -> &AtomicU64 {
        assert!(index < SIZE / 8);
        // mmap은 페이지 정렬되며 모든 오프셋은 AtomicU64 정렬과 크기에 맞는다.
        unsafe { &*(self.map.as_ptr().add(index * 8).cast::<AtomicU64>()) }
    }
    pub fn publish(
        &mut self,
        sessions: &[NatSession],
        state: TunnelState,
        heartbeat_ms: u64,
    ) -> Result<()> {
        ensure!(
            self.writer && sessions.len() <= MAX_SESSIONS,
            "공유 상태 쓰기 권한 또는 세션 한도 오류"
        );
        let generation = self.word(1).load(Ordering::SeqCst);
        ensure!(generation & 1 == 0, "공유 상태 작성자가 중단됐습니다");
        self.word(1)
            .store(generation.wrapping_add(1), Ordering::SeqCst);
        for (index, session) in sessions.iter().enumerate() {
            let mut row = [0u64; ROW_WORDS];
            row[0] = u64::from(session.flow.protocol as u8);
            row[1] = u64::from(session.pid);
            row[2] = session.created_ms;
            row[3] = session.last_seen_ms;
            for (start, address) in [
                (4, session.flow.client),
                (7, session.flow.target),
                (10, session.alias),
                (13, session.relay),
            ] {
                let ip = match address.ip() {
                    std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
                    std::net::IpAddr::V6(ip) => ip.octets(),
                };
                row[start] = u64::from_be_bytes(ip[..8].try_into()?);
                row[start + 1] = u64::from_be_bytes(ip[8..].try_into()?);
                row[start + 2] = u64::from(address.port());
            }
            for (offset, value) in row.into_iter().enumerate() {
                self.word(HEADER_WORDS + index * ROW_WORDS + offset)
                    .store(value, Ordering::SeqCst);
            }
        }
        self.word(2).store(heartbeat_ms, Ordering::SeqCst);
        self.word(3).store(state as u64, Ordering::SeqCst);
        self.word(4).store(sessions.len() as u64, Ordering::SeqCst);
        self.word(1)
            .store(generation.wrapping_add(2), Ordering::SeqCst);
        Ok(())
    }
    pub fn snapshot(&self) -> Result<SharedSnapshot> {
        for _ in 0..32 {
            let before = self.word(1).load(Ordering::SeqCst);
            if before & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }
            let count = self.word(4).load(Ordering::SeqCst) as usize;
            ensure!(count <= MAX_SESSIONS, "공유 NAT 행 수가 잘못됐습니다");
            let heartbeat_ms = self.word(2).load(Ordering::SeqCst);
            let state = match self.word(3).load(Ordering::SeqCst) {
                2 => TunnelState::Connected,
                1 => TunnelState::Reconnecting,
                _ => TunnelState::Down,
            };
            let rows = (0..count)
                .map(|index| {
                    std::array::from_fn(|offset| {
                        self.word(HEADER_WORDS + index * ROW_WORDS + offset)
                            .load(Ordering::SeqCst)
                    })
                })
                .collect();
            if self.word(1).load(Ordering::SeqCst) == before {
                return Ok(SharedSnapshot {
                    heartbeat_ms,
                    state,
                    rows,
                });
            }
        }
        bail!("공유 상태가 변경 중이거나 작성자가 중단됐습니다")
    }
}
