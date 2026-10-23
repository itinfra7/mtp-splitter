//! 진단 뒤 사용자가 없는 앱 소유 드라이버만 정상 SCM 절차로 중지한다.
//! watchdog의 차단 핸들이나 다른 앱의 핸들이 있으면 서비스를 건드리지 않는다.

use super::divert::DivertApi;
use crate::paths::AppPaths;
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashSet,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0},
    System::{
        Services::*,
        Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject},
    },
};

struct InstallMutex(HANDLE);
impl Drop for InstallMutex {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}
struct ServiceHandle(SC_HANDLE);
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupResult {
    Stopped,
    InUse,
    Foreign,
    Absent,
}

pub fn cleanup_idle(paths: &AppPaths, api: &Arc<DivertApi>) -> Result<CleanupResult> {
    // 공식 DLL과 같은 설치 뮤텍스를 사용한다. 무기한 대기하지 않는다.
    let name = wide("WinDivertDriverInstallMutex");
    let raw = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    ensure!(
        !raw.is_null(),
        "드라이버 정리 뮤텍스 생성 실패: {}",
        std::io::Error::last_os_error()
    );
    let waited = unsafe { WaitForSingleObject(raw, 5000) };
    if waited != WAIT_OBJECT_0 && waited != WAIT_ABANDONED {
        unsafe {
            CloseHandle(raw);
        }
        anyhow::bail!("드라이버 정리 뮤텍스 대기 실패 또는 시간 초과");
    }
    let _mutex = InstallMutex(raw);
    // NO_INSTALL은 정리 목적으로 새 드라이버를 설치하는 일을 막는다.
    let reflection = match api.open("true", 4, 0, 0x1 | 0x4 | 0x10) {
        Ok(handle) => handle,
        Err(error)
            if matches!(
                error
                    .downcast_ref::<std::io::Error>()
                    .and_then(std::io::Error::raw_os_error),
                Some(2 | 1060)
            ) =>
        {
            return Ok(CleanupResult::Absent);
        }
        Err(error) => return Err(error),
    };
    reflection.shutdown()?;
    let mut users = HashSet::new();
    let mut buffer = vec![0; 65575];
    loop {
        match reflection.receive(&mut buffer) {
            Ok((_, address)) => {
                ensure!(address.bits & 255 == 4, "잘못된 REFLECT 계층 주소입니다");
                if address.event() == 8 {
                    let pid = u32::from_ne_bytes(address.data[8..12].try_into()?);
                    users.insert(pid);
                }
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .and_then(std::io::Error::raw_os_error)
                    == Some(232) =>
            {
                break;
            }
            Err(error) => return Err(error).context("드라이버 사용자 목록 확인 실패"),
        }
    }
    drop(reflection);
    if !users.is_empty() {
        println!("다른 WinDivert 핸들을 보유한 PID {users:?}가 있어 서비스 중지를 생략합니다");
        return Ok(CleanupResult::InUse);
    }
    let manager = ServiceHandle(unsafe {
        OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT)
    });
    ensure!(
        !manager.0.is_null(),
        "SCM 연결 실패: {}",
        std::io::Error::last_os_error()
    );
    let name = wide("WinDivert");
    let raw = unsafe {
        OpenServiceW(
            manager.0,
            name.as_ptr(),
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP,
        )
    };
    if raw.is_null() {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(1060) {
            return Ok(CleanupResult::Absent);
        }
        return Err(error).context("드라이버 서비스 조회 실패");
    }
    let service = ServiceHandle(raw);
    let mut needed = 0;
    unsafe {
        QueryServiceConfigW(service.0, std::ptr::null_mut(), 0, &mut needed);
    }
    ensure!(
        needed > 0 && needed <= 65536,
        "서비스 설정 크기가 잘못됐습니다"
    );
    // 구조체와 뒤따르는 문자열을 포인터 정렬이 보장되는 한 버퍼에서 읽는다.
    let mut storage = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    let configuration = storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    ensure!(
        unsafe { QueryServiceConfigW(service.0, configuration, needed, &mut needed) } != 0,
        "서비스 설정 조회 실패: {}",
        std::io::Error::last_os_error()
    );
    let configuration = unsafe { &*configuration };
    ensure!(
        configuration.dwServiceType == SERVICE_KERNEL_DRIVER,
        "커널 드라이버 서비스가 아닙니다"
    );
    let start = configuration.lpBinaryPathName as usize;
    let end = storage.as_ptr() as usize + std::mem::size_of_val(storage.as_slice());
    ensure!(
        start >= storage.as_ptr() as usize && start < end && start.is_multiple_of(2),
        "서비스 경로 포인터가 버퍼 밖입니다"
    );
    let text =
        unsafe { std::slice::from_raw_parts(configuration.lpBinaryPathName, (end - start) / 2) };
    let length = text
        .iter()
        .position(|unit| *unit == 0)
        .context("서비스 경로가 끝나지 않습니다")?;
    let text = String::from_utf16(&text[..length])?;
    let text = text.trim_matches('"');
    let text = text.strip_prefix(r"\??\").unwrap_or(text);
    let actual = PathBuf::from(text).canonicalize()?;
    if actual != paths.resolve("bin/WinDivert64.sys")?.canonicalize()? {
        println!(
            "다른 경로의 WinDivert 서비스이므로 중지를 생략합니다: {}",
            actual.display()
        );
        return Ok(CleanupResult::Foreign);
    }
    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    if unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) } == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(1062) {
            return Err(error).context("사용하지 않는 앱 드라이버 중지 실패");
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        ensure!(
            unsafe { QueryServiceStatus(service.0, &mut status) } != 0,
            "드라이버 중지 상태 조회 실패: {}",
            std::io::Error::last_os_error()
        );
        if status.dwCurrentState == SERVICE_STOPPED {
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "드라이버가 5초 안에 중지되지 않았습니다"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // DLL이 이미 삭제 대기로 표시했다. 별도 영구 서비스나 레지스트리 항목을 생성하지 않는다.
    println!("사용하지 않는 앱 WinDivert 드라이버를 SCM으로 중지했습니다");
    Ok(CleanupResult::Stopped)
}
