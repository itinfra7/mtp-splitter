//! 현재 작업 디렉터리와 무관하게 실행 파일을 기준으로 쓰기 경로를 고정한다.

use anyhow::{Context, Result, bail};
use std::{
    fs::{self, File, OpenOptions},
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct AppPaths {
    root: PathBuf,
}

impl AppPaths {
    pub fn discover() -> Result<Self> {
        let executable = std::env::current_exe()?.canonicalize()?;
        let parent = executable
            .parent()
            .context("실행 파일의 상위 경로가 없습니다")?;
        // watchdog은 bin 안에 있으므로 한 단계 위를 앱 루트로 사용한다.
        let root = if executable.file_stem().is_some_and(|s| s == "watchdog") {
            if parent.file_name().is_none_or(|s| s != "bin") {
                bail!("watchdog은 앱의 bin 폴더에서 실행해야 합니다");
            }
            parent.parent().context("앱 루트가 없습니다")?.to_path_buf()
        } else {
            parent.to_path_buf()
        };
        Self::new(root)
    }

    pub fn new(root: PathBuf) -> Result<Self> {
        if !root.is_absolute() {
            bail!("앱 루트는 절대 경로여야 합니다");
        }
        Ok(Self {
            root: root.canonicalize()?,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// 기존 상위 폴더의 정션·심볼릭 링크도 검사해 루트 외부 쓰기를 거부한다.
    pub fn resolve(&self, relative: impl AsRef<Path>) -> Result<PathBuf> {
        let relative = relative.as_ref();
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            bail!("앱 내부의 일반 상대 경로만 허용됩니다");
        }
        let path = self.root.join(relative);
        let mut cursor = self.root.clone();
        for part in relative.components() {
            cursor.push(part.as_os_str());
            match fs::symlink_metadata(&cursor) {
                Ok(_) => {
                    if !cursor.canonicalize()?.starts_with(&self.root) {
                        bail!("경로가 앱 루트 밖을 가리킵니다");
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(path)
    }

    pub fn prepare(&self) -> Result<()> {
        for name in ["bin", "config", "runtime", "logs"] {
            fs::create_dir_all(self.resolve(name)?)?;
        }
        Ok(())
    }

    pub fn lock(&self) -> Result<File> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.resolve("runtime/instance.lock")?)?;
        fs2::FileExt::try_lock_exclusive(&file).context("이미 실행 중인 인스턴스가 있습니다")?;
        Ok(file)
    }

    /// 같은 디렉터리에서 임시 파일을 만든 뒤 교체한다. 실패 시 이전 파일은 보존한다.
    pub fn atomic_write(&self, relative: &str, contents: &[u8]) -> Result<()> {
        use std::io::Write;
        let target = self.resolve(relative)?;
        let temporary = target.with_extension(format!("tmp-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let result = (|| -> Result<()> {
            file.write_all(contents)?;
            file.sync_all()?;
            drop(file);
            #[cfg(windows)]
            {
                use std::os::windows::ffi::OsStrExt;
                use windows_sys::Win32::Storage::FileSystem::{
                    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
                };
                let from: Vec<_> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
                let to: Vec<_> = target.as_os_str().encode_wide().chain(Some(0)).collect();
                // 두 버퍼는 호출이 끝날 때까지 유효하며 널로 종료된다.
                if unsafe {
                    MoveFileExW(
                        from.as_ptr(),
                        to.as_ptr(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                    )
                } == 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            #[cfg(not(windows))]
            fs::rename(&temporary, &target)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}
