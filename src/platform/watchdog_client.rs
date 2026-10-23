//! 메인 프로세스가 소유하는 로컬 named pipe와 별도 watchdog 실행 수명이다.
//! 연결 객체의 Drop은 파이프를 끊어 차단을 고정하며 자동 해제나 강제 종료를 수행하지 않는다.

use crate::{
    paths::AppPaths,
    watchdog::{PIPE_NAME, RelayPorts},
};
use anyhow::{Context, Result, ensure};
use std::{
    os::windows::{io::AsRawHandle, process::CommandExt},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

pub struct WatchdogConnection {
    pipe: NamedPipeServer,
    child: Child,
    token: zeroize::Zeroizing<Vec<u8>>,
}
impl WatchdogConnection {
    pub async fn start(paths: &AppPaths, ports: RelayPorts) -> Result<Self> {
        ports.exemption()?;
        drop(super::guard_lock::root_lock(paths)?);
        let executable = paths.resolve("bin/watchdog.exe")?;
        ensure!(executable.is_file(), "bin/watchdog.exe가 없습니다");
        let pipe = ServerOptions::new()
            .first_pipe_instance(true)
            .max_instances(1)
            .reject_remote_clients(true)
            .create(PIPE_NAME)
            .context("감시 파이프 생성 실패. 다른 인스턴스의 감시가 남아 있는지 확인하십시오")?;
        let child = Command::new(executable)
            .arg("--parent")
            .arg(std::process::id().to_string())
            .arg("--tcp-relay-port")
            .arg(ports.tcp.to_string())
            .arg("--udp-relay-port")
            .arg(ports.udp.to_string())
            .current_dir(paths.root())
            .creation_flags(0x08000000)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("watchdog 실행 실패")?;
        let mut connection = Self {
            pipe,
            child,
            token: zeroize::Zeroizing::new(Vec::new()),
        };
        let pid = connection.pid();
        let result = tokio::time::timeout(Duration::from_secs(40), async {
            connection.pipe.connect().await?;
            let mut actual_pid = 0;
            ensure!(
                unsafe {
                    GetNamedPipeClientProcessId(
                        connection.pipe.as_raw_handle().cast(),
                        &mut actual_pid,
                    )
                } != 0
                    && actual_pid == pid,
                "감시 파이프 클라이언트 PID가 다릅니다"
            );
            let mut ready = [0; 4];
            connection.pipe.read_exact(&mut ready).await?;
            ensure!(&ready == b"RDY1", "watchdog 준비 응답이 잘못됐습니다");
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("watchdog 준비 응답 시간 초과")
        .and_then(|result| result);
        if let Err(error) = result {
            anyhow::bail!(
                "watchdog PID {pid} 준비 실패: {error:#}. 이미 차단이 시작됐다면 release --watchdog-pid {pid}로 명시적으로 해제하십시오"
            );
        }
        connection.token = zeroize::Zeroizing::new(std::fs::read(
            paths.resolve(format!("runtime/watchdog-{pid}.token"))?,
        )?);
        ensure!(
            connection.token.len() == 64 && connection.token.iter().all(u8::is_ascii_hexdigit),
            "감시 해제 토큰이 잘못됐습니다"
        );
        Ok(connection)
    }
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
    pub fn healthy(&mut self) -> Result<()> {
        ensure!(
            self.child.try_wait()?.is_none(),
            "watchdog PID {}가 종료됐습니다",
            self.pid()
        );
        Ok(())
    }
    pub async fn heartbeat(&mut self) -> Result<()> {
        self.healthy()?;
        tokio::time::timeout(Duration::from_secs(2), self.pipe.write_all(b"PING"))
            .await
            .context("watchdog heartbeat 전송 시간 초과")??;
        Ok(())
    }
    pub fn release_requested(&self, paths: &AppPaths) -> Result<bool> {
        use subtle::ConstantTimeEq;
        match std::fs::read(paths.resolve(format!("runtime/watchdog-{}.stop-main", self.pid()))?) {
            Ok(bytes) => Ok(bytes.ct_eq(self.token.as_slice()).unwrap_u8() == 1),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    pub fn remove_notice(&self, paths: &AppPaths) -> Result<()> {
        match std::fs::remove_file(
            paths.resolve(format!("runtime/watchdog-{}.stop-main", self.pid()))?,
        ) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    /// 사용자가 명시적으로 정지·해제를 요청한 경로에서만 호출한다.
    pub async fn release(&mut self, paths: &AppPaths) -> Result<()> {
        if let Some(status) = self.child.try_wait()? {
            ensure!(
                status.success(),
                "watchdog 정리 중 오류가 발생했습니다: {status}"
            );
            return Ok(());
        }
        let sent = tokio::time::timeout(Duration::from_secs(2), self.pipe.write_all(b"QUIT")).await;
        if !matches!(sent, Ok(Ok(()))) {
            crate::watchdog::request_release(paths, self.pid())?;
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait()? {
                ensure!(
                    status.success(),
                    "watchdog 정리 중 오류가 발생했습니다: {status}"
                );
                return Ok(());
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "watchdog PID {}가 해제 기한 안에 종료되지 않았습니다",
                self.pid()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
