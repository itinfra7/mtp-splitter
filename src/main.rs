//! 실제 설정·프로토콜·DNS를 검증하는 CLI이다. 실행 가능한 명령만 노출한다.
#![cfg_attr(windows, windows_subsystem = "windows")]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use mtp_splitter::{
    config,
    fake_dns::{self, FakeIpCache},
    mtproto_core::{self, ClientHello, ObfuscatedStream, TransportTag},
    paths::AppPaths,
};
use std::{
    io::Write,
    net::{SocketAddr, TcpStream},
    num::NonZeroUsize,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Parser)]
#[command(
    name = "mtp-splitter",
    version,
    about = "애플리케이션별 터널링 구성 요소와 연결 진단"
)]
struct Arguments {
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    #[command(about = "컴팩트한 데스크톱 제어창을 엽니다")]
    Gui,
    #[command(about = "서버가 발급한 비공개 ZIP을 앱 내부에 가져옵니다")]
    ImportClient { archive: std::path::PathBuf },
    #[command(about = "앱 규칙을 보존하고 서버 설정과 인증서를 삭제합니다")]
    ClearServer,
    #[command(about = "규칙에 일치하는 앱의 TCP·UDP·DNS를 확장 게이트웨이로 전환합니다")]
    Run {
        #[arg(long, default_value_t = 17001)]
        tcp_port: u16,
        #[arg(long, default_value_t = 17002)]
        udp_port: u16,
        #[arg(
            long,
            help = "사용자 종료 신호를 받으면 watchdog의 차단도 명시적으로 해제합니다"
        )]
        release_on_exit: bool,
    },
    #[command(about = "설정과 앱 내부 경로를 검사합니다")]
    Doctor,
    #[command(about = "앱 bin의 실제 WinDivert DLL과 선택적인 비포착 커널 핸들을 검사합니다")]
    DriverCheck {
        #[arg(long, help = "false 필터로 커널 핸들을 잠깐 열어 확인합니다")]
        kernel: bool,
        #[arg(
            long,
            help = "전용 테스트 소켓만 포착해 실제 커널 NAT 왕복을 검사합니다"
        )]
        nat: bool,
    },
    #[command(about = "설정한 MTProxy의 실제 Fake-TLS 응답을 인증합니다")]
    Probe,
    #[command(about = "확장 게이트웨이의 상호 TLS 인증과 WELCOME 응답을 검증합니다")]
    GatewayProbe,
    #[command(about = "도메인의 Fake-IP DNS 응답을 생성하고 캐시를 저장합니다")]
    Dns {
        domain: String,
        #[arg(long, default_value_t = false)]
        aaaa: bool,
    },
    #[command(about = "프로세스 규칙에 일치하는 실행 이미지와 자식을 표시합니다")]
    Processes,
    #[command(about = "프로세스와 SOCKET 이벤트를 지속 감시합니다. 패킷 전환은 수행하지 않습니다")]
    Monitor {
        #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=3600))]
        seconds: u64,
    },
    #[command(about = "지정한 watchdog의 차단 해제를 명시적으로 요청합니다")]
    Release {
        #[arg(long)]
        watchdog_pid: u32,
    },
}

fn main() {
    #[cfg(windows)]
    if std::env::args_os().len() > 1 {
        // CLI 호출만 부모 콘솔에 연결한다. 더블클릭 GUI에는 콘솔 창을 만들지 않는다.
        unsafe {
            windows_sys::Win32::System::Console::AttachConsole(u32::MAX);
        }
    }
    if let Err(error) = execute() {
        eprintln!("오류: {error:#}");
        #[cfg(windows)]
        if std::env::args_os().len() == 1 {
            let message: Vec<_> = format!("실행 오류: {error:#}")
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let title: Vec<_> = "mtp-splitter".encode_utf16().chain(Some(0)).collect();
            unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
                    std::ptr::null_mut(),
                    message.as_ptr(),
                    title.as_ptr(),
                    0x10,
                );
            }
        }
        std::process::exit(1);
    }
}
fn execute() -> Result<()> {
    let arguments = Arguments::parse();
    let paths = AppPaths::discover()?;
    paths.prepare()?;
    mtp_splitter::logging::install(&paths)?;
    match arguments.command.unwrap_or(Command::Gui) {
        Command::ClearServer => {
            mtp_splitter::client_bundle::clear_server(&paths)?;
            println!("서버 설정을 삭제했습니다");
        }
        Command::ImportClient { archive } => {
            mtp_splitter::client_bundle::ClientBundle::read(&archive)?.install(&paths)?;
            println!("서버 구성과 인증서를 앱 내부로 가져왔습니다. 비밀값은 출력하지 않았습니다.");
        }
        Command::Gui => {
            #[cfg(windows)]
            mtp_splitter::platform::gui::run(std::sync::Arc::new(paths))?;
            #[cfg(not(windows))]
            anyhow::bail!("GUI는 Windows에서만 지원됩니다");
        }
        Command::Run {
            tcp_port,
            udp_port,
            release_on_exit,
        } => {
            #[cfg(windows)]
            {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()?;
                let outcome = runtime.block_on(mtp_splitter::platform::runtime::run_until(
                    std::sync::Arc::new(paths),
                    mtp_splitter::platform::runtime::RunOptions {
                        tcp_port,
                        udp_port,
                        release_on_exit,
                    },
                    async { tokio::signal::ctrl_c().await.context("종료 신호 등록 실패") },
                ))?;
                if outcome.released {
                    println!("터널과 watchdog을 종료하고 차단을 해제했습니다");
                } else {
                    println!("watchdog PID={}가 차단을 유지합니다", outcome.watchdog_pid);
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (tcp_port, udp_port, release_on_exit);
                anyhow::bail!("투명 터널 실행은 Windows에서만 지원됩니다");
            }
        }
        Command::DriverCheck { kernel, nat } => {
            #[cfg(windows)]
            mtp_splitter::platform::diagnostics::check(&paths, kernel, nat)?;
            #[cfg(not(windows))]
            {
                let _ = (kernel, nat);
                anyhow::bail!("WinDivert 검사는 Windows에서만 지원됩니다");
            }
        }
        Command::Doctor => {
            let (server, rules) = config::load(&paths)?;
            server.endpoint_ip()?;
            for rule in rules.iter().cloned() {
                mtp_splitter::process_tracker::CompiledRule::new(rule)?;
            }
            println!("앱 루트: {}", paths.root().display());
            println!("서버 설정과 프로세스 규칙 {}개가 유효합니다", rules.len());
            for name in [
                "bin/WinDivert.dll",
                "bin/WinDivert64.sys",
                "bin/watchdog.exe",
            ] {
                println!(
                    "{name}: {}",
                    if paths.resolve(name)?.is_file() {
                        "있음"
                    } else {
                        "없음"
                    }
                );
            }
            println!(
                "실행에는 확장 게이트웨이와 운영 인증서가 필요합니다. run --help를 확인하십시오."
            );
        }
        Command::Probe => {
            let (server, _) = config::load(&paths)?;
            let secret = server.validate()?;
            let timeout = Duration::from_secs(server.timeout_seconds);
            let mut stream = TcpStream::connect_timeout(
                &SocketAddr::new(server.endpoint_ip()?, server.port),
                timeout,
            )?;
            stream.set_read_timeout(Some(timeout))?;
            stream.set_write_timeout(Some(timeout))?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let hello =
                ClientHello::generate(&secret, u32::try_from(now)?, &mut rand::rngs::OsRng)?;
            stream.write_all(&hello.wire)?;
            let response = mtproto_core::read_server_hello(&mut stream)?;
            mtproto_core::verify_server_hello(&secret, &hello, &response)?;
            let (init, _) = ObfuscatedStream::client(
                &secret,
                server.dc_id,
                TransportTag::PaddedIntermediate,
                &mut rand::rngs::OsRng,
            )?;
            stream.write_all(&[0x14, 3, 3, 0, 1, 1])?;
            mtproto_core::write_tls_records(&mut stream, &init)?;
            println!(
                "Fake-TLS 서버 응답의 HMAC 인증이 성공했습니다. 임의 TCP·UDP 중계 지원을 확인한 결과는 아닙니다."
            );
        }
        Command::GatewayProbe => {
            let server = config::load_server(&paths)?;
            let security = mtp_splitter::transport::SecurityConfig::load(&paths)?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let (_, settings) =
                runtime.block_on(mtp_splitter::transport::connect(&server, &security, &paths))?;
            println!(
                "게이트웨이의 Fake-TLS·상호 TLS 1.3 인증과 WELCOME 검증이 성공했습니다. 기능 비트: {}",
                settings.capabilities
            );
        }
        Command::Dns { domain, aaaa } => {
            let _lock = paths.lock()?;
            let mut cache =
                FakeIpCache::load(&paths, NonZeroUsize::new(8192).context("캐시 용량 오류")?)?;
            let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            fake_dns::encode_name(&domain, &mut query)?;
            query.extend_from_slice(&(if aaaa { 28u16 } else { 1u16 }).to_be_bytes());
            query.extend_from_slice(&[0, 1]);
            let response = fake_dns::synthesize(
                &query,
                &mut cache,
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            )?;
            cache.persist(&paths)?;
            println!("DNS 응답: {}", hex::encode(response));
        }
        Command::Processes => {
            #[cfg(windows)]
            {
                let (_, rules) = config::load(&paths)?;
                let mut tracker = mtp_splitter::process_tracker::ProcessTracker::new(
                    rules,
                    [std::process::id()],
                )?;
                tracker.refresh(&mtp_splitter::platform::processes::snapshot()?)?;
                for process in tracker.tracked() {
                    println!(
                        "PID={} 부모={} 자식상속={} {}",
                        process.identity.pid,
                        process.identity.parent,
                        process.inherit,
                        process.identity.image.display()
                    );
                }
            }
            #[cfg(not(windows))]
            anyhow::bail!("프로세스 열거는 Windows에서만 지원됩니다");
        }
        Command::Release { watchdog_pid } => {
            mtp_splitter::watchdog::request_release(&paths, watchdog_pid)?
        }
        Command::Monitor { seconds } => {
            #[cfg(windows)]
            {
                let (_, rules) = config::load(&paths)?;
                mtp_splitter::platform::monitor::diagnose(&paths, rules, seconds)?;
            }
            #[cfg(not(windows))]
            {
                let _ = seconds;
                anyhow::bail!("SOCKET 감시는 Windows에서만 지원됩니다");
            }
        }
    }
    Ok(())
}
