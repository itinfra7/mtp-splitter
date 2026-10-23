//! 메인 프로세스와 별도의 주소 공간에서 커널 차단 핸들을 유지한다.

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(about = "메인 종료 후에도 차단과 신규 소켓 감시를 유지하는 감시 프로세스")]
struct Arguments {
    #[arg(long, help = "감시 파이프를 만든 메인 프로세스 PID")]
    parent: u32,
    #[arg(long)]
    tcp_relay_port: u16,
    #[arg(long)]
    udp_relay_port: u16,
}

fn main() {
    if let Err(error) = execute() {
        tracing::error!(%error, "watchdog 실행 실패");
        eprintln!("watchdog 오류: {error:#}");
        std::process::exit(1);
    }
}

fn execute() -> Result<()> {
    let args = Arguments::parse();
    #[cfg(windows)]
    {
        let paths = mtp_splitter::paths::AppPaths::discover()?;
        paths.prepare()?;
        mtp_splitter::logging::install_named(&paths, "logs/watchdog.log")?;
        mtp_splitter::watchdog::run(
            args.parent,
            mtp_splitter::watchdog::RelayPorts {
                tcp: args.tcp_relay_port,
                udp: args.udp_relay_port,
            },
        )
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        anyhow::bail!("watchdog 실행은 Windows에서만 지원됩니다")
    }
}
