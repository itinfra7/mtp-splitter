//! JSON 로그를 지정된 크기에서 회전하며 모든 파일을 앱 logs 안에 둔다.

use crate::paths::AppPaths;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tracing_subscriber::fmt::MakeWriter;

struct RotatingFile {
    path: PathBuf,
    file: File,
    size: u64,
    limit: u64,
    backups: u32,
}
impl RotatingFile {
    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;
        // Windows는 열린 파일의 이름 변경을 제한하므로 공유 삭제 플래그로 연다.
        for index in (1..=self.backups).rev() {
            let target = self.path.with_extension(format!("log.{index}"));
            let source = if index == 1 {
                self.path.clone()
            } else {
                self.path.with_extension(format!("log.{}", index - 1))
            };
            if target.exists() {
                fs::remove_file(&target)?;
            }
            if source.exists() {
                fs::rename(&source, &target)?;
            }
        }
        self.file = open(&self.path)?;
        self.size = 0;
        Ok(())
    }
}
fn open(path: &PathBuf) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1 | 2 | 4);
    }
    options.open(path)
}
#[derive(Clone)]
pub struct LogWriter(Arc<Mutex<RotatingFile>>);
impl LogWriter {
    pub fn new(paths: &AppPaths, limit: u64, backups: u32) -> anyhow::Result<Self> {
        Self::new_named(paths, "logs/tunnel.log", limit, backups)
    }
    pub fn new_named(
        paths: &AppPaths,
        relative: &str,
        limit: u64,
        backups: u32,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            limit >= 1024 && (1..=32).contains(&backups),
            "로그 회전 한도가 잘못됐습니다"
        );
        let path = paths.resolve(relative)?;
        let file = open(&path)?;
        let size = file.metadata()?.len();
        Ok(Self(Arc::new(Mutex::new(RotatingFile {
            path,
            file,
            size,
            limit,
            backups,
        }))))
    }
}
impl Write for LogWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut log = self
            .0
            .lock()
            .map_err(|_| io::Error::other("로그 잠금 손상"))?;
        if log.size > 0 && log.size.saturating_add(data.len() as u64) > log.limit {
            log.rotate()?;
        }
        log.file.write_all(data)?;
        log.size += data.len() as u64;
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("로그 잠금 손상"))?
            .file
            .flush()
    }
}
impl<'a> MakeWriter<'a> for LogWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

pub fn install(paths: &AppPaths) -> anyhow::Result<()> {
    install_named(paths, "logs/tunnel.log")
}
pub fn install_named(paths: &AppPaths, relative: &str) -> anyhow::Result<()> {
    use tracing_subscriber::prelude::*;
    let writer = LogWriter::new_named(paths, relative, 8 * 1024 * 1024, 4)?;
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_env("MTP_SPLITTER_LOG").unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(
                    "info,wgpu=warn,wgpu_core=warn,wgpu_hal=warn,naga=warn",
                )
            }),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_ansi(false)
                .with_writer(writer),
        )
        .try_init()?;
    Ok(())
}
