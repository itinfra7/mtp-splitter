//! 충돌 후 남아 있는 watchdog과 새 실행이 공유 상태를 동시에 소유하지 못하게 한다.

use crate::paths::AppPaths;
use anyhow::{Context, Result, ensure};
use std::fs::{File, OpenOptions};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0},
    System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject},
};

pub fn root_lock(paths: &AppPaths) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(paths.resolve("runtime/watchdog.lock")?)?;
    fs2::FileExt::try_lock_exclusive(&file)
        .context("이 앱의 watchdog이 차단을 유지하고 있습니다. 해당 PID의 차단을 먼저 명시적으로 해제하십시오")?;
    Ok(file)
}

/// 파이프 서버가 사라져도 프로세스가 종료될 때까지 호스트의 중복 감시를 거부한다.
/// Windows 뮤텍스 소유권은 획득한 스레드에서 해제해야 하므로 비동기 작업으로 옮기지 않는다.
pub struct HostGuard {
    handle: HANDLE,
    _same_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl HostGuard {
    pub fn acquire() -> Result<Self> {
        let name: Vec<u16> = "Global\\mtp-splitter-watchdog"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        ensure!(
            !handle.is_null(),
            "호스트 감시 뮤텍스 생성 실패: {}",
            std::io::Error::last_os_error()
        );
        let waited = unsafe { WaitForSingleObject(handle, 0) };
        if waited != WAIT_OBJECT_0 && waited != WAIT_ABANDONED {
            unsafe {
                CloseHandle(handle);
            }
            anyhow::bail!("다른 watchdog이 호스트의 차단을 유지하고 있습니다");
        }
        Ok(Self {
            handle,
            _same_thread: std::marker::PhantomData,
        })
    }
}
impl Drop for HostGuard {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.handle);
            CloseHandle(self.handle);
        }
    }
}
