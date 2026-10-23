//! 메인 연결이 끊겨도 차단을 유지하며 명시적인 해제만 수락하는 감시 정책이다.

use anyhow::{Result, ensure};
use std::time::{Duration, Instant};

pub const PIPE_NAME: &str = r"\\.\pipe\mtprotoguard_wd";

#[derive(Clone, Copy, Debug)]
pub struct RelayPorts {
    pub tcp: u16,
    pub udp: u16,
}
impl RelayPorts {
    pub fn exemption(&self) -> Result<String> {
        ensure!(
            self.tcp != 0 && self.udp != 0,
            "감시 릴레이 포트는 0일 수 없습니다"
        );
        let mut terms = Vec::new();
        for (protocol, port) in [("tcp", self.tcp), ("udp", self.udp)] {
            terms.push(format!("({protocol} and ((ip.SrcAddr == 127.0.0.2 and ip.DstAddr == 127.0.0.1 and {protocol}.DstPort == {port}) or (ip.SrcAddr == 127.0.0.1 and ip.DstAddr == 127.0.0.2 and {protocol}.SrcPort == {port}) or (ipv6.SrcAddr == ::1 and ipv6.DstAddr == ::1 and ({protocol}.SrcPort == {port} or {protocol}.DstPort == {port}))))"));
        }
        Ok(format!("({})", terms.join(" or ")))
    }
    pub fn guard_filter(&self) -> Result<String> {
        Ok(format!(
            "outbound and (tcp or udp or fragment) and ({} ? false : true)",
            self.exemption()?
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardState {
    Starting,
    Protecting,
    Latched,
    Released,
}

pub struct WatchdogPolicy {
    state: GuardState,
    last_heartbeat: Instant,
    timeout: Duration,
}
impl WatchdogPolicy {
    pub fn new(now: Instant, timeout: Duration) -> Result<Self> {
        ensure!(
            !timeout.is_zero() && timeout <= Duration::from_secs(60),
            "감시 제한 시간이 잘못됐습니다"
        );
        Ok(Self {
            state: GuardState::Starting,
            last_heartbeat: now,
            timeout,
        })
    }
    pub fn ready(&mut self, now: Instant) {
        if self.state == GuardState::Starting {
            self.last_heartbeat = now;
            self.state = GuardState::Protecting;
        }
    }
    pub fn heartbeat(&mut self, now: Instant) {
        if self.state == GuardState::Protecting {
            self.last_heartbeat = now;
        }
    }
    pub fn broken_pipe(&mut self) {
        if self.state != GuardState::Released {
            self.state = GuardState::Latched;
        }
    }
    pub fn tick(&mut self, now: Instant) {
        if self.state != GuardState::Released
            && now.saturating_duration_since(self.last_heartbeat) >= self.timeout
        {
            self.state = GuardState::Latched;
        }
    }
    pub fn release(&mut self) {
        self.state = GuardState::Released;
    }
    pub fn state(&self) -> GuardState {
        self.state
    }
}

/// 공유 스냅숏의 원래 송신 소켓을 진단용 필터 표현식으로 변환한다.
/// 실행 중 차단은 포트 재사용을 구분하는 독립 프로세스·소켓 감시기가 수행한다.
pub fn flow_filters(snapshot: &crate::shared_state::SharedSnapshot) -> Result<Vec<String>> {
    use std::{collections::BTreeSet, net::Ipv6Addr};
    let mut expressions = BTreeSet::new();
    for row in &snapshot.rows {
        let protocol = match row[0] {
            6 => "tcp",
            17 => "udp",
            _ => anyhow::bail!("공유 상태의 프로토콜이 잘못됐습니다"),
        };
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&row[4].to_be_bytes());
        bytes[8..].copy_from_slice(&row[5].to_be_bytes());
        let ip = Ipv6Addr::from(bytes);
        let port = u16::try_from(row[6])?;
        ensure!(port != 0, "공유 상태의 로컬 포트가 0입니다");
        let address = if let Some(ip) = ip.to_ipv4_mapped() {
            format!("ip.SrcAddr == {ip}")
        } else {
            format!("ipv6.SrcAddr == {ip}")
        };
        expressions.insert(format!(
            "({protocol} and {protocol}.SrcPort == {port} and {address})"
        ));
    }
    let expressions: Vec<_> = expressions.into_iter().collect();
    Ok(expressions
        .chunks(48)
        .map(|chunk| format!("outbound and ({})", chunk.join(" or ")))
        .collect())
}

#[cfg(windows)]
pub fn run(parent_pid: u32, relay_ports: RelayPorts) -> Result<()> {
    use crate::{
        nat_engine::{NatSessionTable, TunnelStatus},
        packet_router::PacketRouter,
        paths::AppPaths,
        platform::{divert::DivertApi, monitor::ProcessMonitor, network::NetworkEngine},
        process_tracker::ActiveSocketTable,
        shared_state::SharedState,
    };
    use rand::RngCore;
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::io::{AsRawHandle, FromRawHandle},
        sync::{Arc, mpsc},
    };
    use windows_sys::Win32::{
        Foundation::INVALID_HANDLE_VALUE,
        Storage::FileSystem::{CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING},
        System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW},
    };

    let paths = AppPaths::discover()?;
    paths.prepare()?;
    let _root_lock = crate::platform::guard_lock::root_lock(&paths)?;
    let _host_guard = crate::platform::guard_lock::HostGuard::acquire()?;
    let name: Vec<_> = PIPE_NAME.encode_utf16().chain(Some(0)).collect();
    ensure!(
        unsafe { WaitNamedPipeW(name.as_ptr(), 5000) } != 0,
        "메인 감시 파이프를 찾지 못했습니다: {}",
        std::io::Error::last_os_error()
    );
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    ensure!(
        raw != INVALID_HANDLE_VALUE,
        "감시 파이프 연결 실패: {}",
        std::io::Error::last_os_error()
    );
    let mut pipe = unsafe { std::fs::File::from_raw_handle(raw) };
    let mut server_pid = 0;
    ensure!(
        unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle().cast(), &mut server_pid) } != 0
            && server_pid == parent_pid,
        "감시 파이프 서버 PID가 다릅니다"
    );
    let parent = crate::platform::processes::observe(parent_pid, 0)?;
    let shared = SharedState::open(&paths, false)?;
    let api = DivertApi::load(&paths)?;
    let (_, rules) = crate::config::load(&paths)?;
    let started = Instant::now();
    let excluded = [parent_pid, std::process::id()];
    let router = Arc::new(PacketRouter::new(
        Arc::new(NatSessionTable::new(1, 0, 0)),
        Arc::new(ActiveSocketTable::default()),
        Arc::new(TunnelStatus::default()),
        excluded,
    ));
    let monitor = ProcessMonitor::start(&api, Arc::clone(&router), rules, excluded, started)?;
    let guard = NetworkEngine::start_at_priority(
        &api,
        router,
        &relay_ports.guard_filter()?,
        -900,
        started,
    )?;
    let mut previous_count = shared.snapshot()?.rows.len();
    let mut token = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut token);
    let token_path = format!("runtime/watchdog-{}.token", std::process::id());
    let release_path = format!("runtime/watchdog-{}.release", std::process::id());
    let mut token_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(paths.resolve(&token_path)?)?;
    token_file.write_all(hex::encode(token).as_bytes())?;
    token_file.sync_all()?;
    let (sender, receiver) = mpsc::sync_channel(16);
    pipe.write_all(b"RDY1")?;
    std::thread::spawn(move || {
        loop {
            let mut command = [0; 4];
            if pipe.read_exact(&mut command).is_err() {
                let _ = sender.send(None);
                break;
            }
            if sender.send(Some(command)).is_err() {
                break;
            }
        }
    });
    let mut policy = WatchdogPolicy::new(Instant::now(), Duration::from_secs(5))?;
    policy.ready(Instant::now());
    let mut latched_reported = false;
    loop {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(Some(command)) if &command == b"PING" => policy.heartbeat(Instant::now()),
            Ok(Some(command)) if &command == b"QUIT" => policy.release(),
            Ok(Some(_)) | Ok(None) => policy.broken_pipe(),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                policy.broken_pipe();
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => (),
        }
        policy.tick(Instant::now());
        if let Err(error) = monitor.healthy().and_then(|()| guard.healthy()) {
            if policy.state() != GuardState::Latched {
                tracing::error!(%error, "독립 감시 오류로 커널 차단을 고정합니다");
            }
            guard.latch();
            policy.broken_pipe();
        }
        if let Ok(contents) = fs::read(paths.resolve(&release_path)?) {
            use subtle::ConstantTimeEq;
            if contents.ct_eq(hex::encode(token).as_bytes()).unwrap_u8() == 1 {
                policy.release();
            }
        }
        if policy.state() == GuardState::Released {
            break;
        }
        if policy.state() == GuardState::Latched {
            if !latched_reported {
                tracing::warn!(
                    pid = std::process::id(),
                    "메인 응답이 끊겼습니다. 기존 차단과 신규 소켓 감시를 유지합니다"
                );
                latched_reported = true;
            }
        } else if let Ok(snapshot) = shared.snapshot() {
            // 포트만 고정 차단하면 종료한 대상 앱의 포트를 재사용한 비대상 앱까지 막게 된다.
            // NAT 공유 상태는 관찰용이며 차단 권한은 현재 PID·생성 시각·소켓 소유권에서 얻는다.
            if snapshot.rows.len() != previous_count {
                previous_count = snapshot.rows.len();
                tracing::debug!(sessions = previous_count, "메인 공유 NAT 세션 수 변경");
            }
        }
    }
    drop(guard);
    drop(monitor);
    drop(shared);
    crate::shared_state::remove_idle(&paths)?;
    for relative in [token_path, release_path] {
        match fs::remove_file(paths.resolve(relative)?) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    if !parent.is_running()? {
        let notice = paths.resolve(format!("runtime/watchdog-{}.stop-main", std::process::id()))?;
        match fs::remove_file(notice) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    // 명시적 해제 뒤에도 다른 핸들이 있으면 서비스를 유지하며 앱 소유 경로만 정리한다.
    crate::platform::driver_service::cleanup_idle(&paths, &api)?;
    Ok(())
}

pub fn request_release(paths: &crate::paths::AppPaths, watchdog_pid: u32) -> Result<()> {
    let token = std::fs::read(paths.resolve(format!("runtime/watchdog-{watchdog_pid}.token"))?)?;
    ensure!(
        token.len() == 64 && token.iter().all(u8::is_ascii_hexdigit),
        "감시 해제 토큰이 잘못됐습니다"
    );
    // 메인도 명시적 해제와 watchdog 충돌을 구분하도록 먼저 지속되는 통지를 쓴다.
    paths.atomic_write(
        &format!("runtime/watchdog-{watchdog_pid}.stop-main"),
        &token,
    )?;
    paths.atomic_write(&format!("runtime/watchdog-{watchdog_pid}.release"), &token)
}
