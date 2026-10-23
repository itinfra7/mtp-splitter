//! 조회 권한만으로 실행 이미지와 생성 시각을 읽어 PID 재사용을 구분한다.

use crate::process_tracker::ProcessIdentity;
use anyhow::{Result, ensure};
use std::{os::windows::ffi::OsStringExt, path::PathBuf};
use windows_sys::Win32::{
    Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE},
    System::{Diagnostics::ToolHelp::*, Threading::*},
};

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

pub struct ObservedProcess {
    pub identity: ProcessIdentity,
    _handle: OwnedHandle,
}
impl ObservedProcess {
    pub fn is_running(&self) -> Result<bool> {
        let mut code = 0;
        ensure!(
            unsafe { GetExitCodeProcess(self._handle.0, &mut code) } != 0,
            "프로세스 종료 상태 조회 실패: {}",
            std::io::Error::last_os_error()
        );
        Ok(code == 259)
    }
}

pub fn identity(pid: u32, parent: u32) -> Result<ProcessIdentity> {
    Ok(observe(pid, parent)?.identity)
}

/// 핸들을 보유하는 동안 종료한 프로세스의 PID가 새 프로세스에 재사용되는 것을 막는다.
pub fn observe(pid: u32, parent: u32) -> Result<ObservedProcess> {
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    ensure!(
        !raw.is_null(),
        "프로세스 {pid} 조회 실패: {}",
        std::io::Error::last_os_error()
    );
    let handle = OwnedHandle(raw);
    let mut path = vec![0; 32768];
    let mut length = path.len() as u32;
    ensure!(
        unsafe { QueryFullProcessImageNameW(handle.0, 0, path.as_mut_ptr(), &mut length) } != 0,
        "프로세스 이미지 조회 실패: {}",
        std::io::Error::last_os_error()
    );
    path.truncate(length as usize);
    let mut creation: FILETIME = unsafe { std::mem::zeroed() };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    ensure!(
        unsafe { GetProcessTimes(handle.0, &mut creation, &mut exit, &mut kernel, &mut user) } != 0,
        "프로세스 생성 시각 조회 실패: {}",
        std::io::Error::last_os_error()
    );
    Ok(ObservedProcess {
        identity: ProcessIdentity {
            pid,
            parent,
            creation_time: (u64::from(creation.dwHighDateTime) << 32)
                | u64::from(creation.dwLowDateTime),
            image: PathBuf::from(std::ffi::OsString::from_wide(&path)),
        },
        _handle: handle,
    })
}

pub fn snapshot() -> Result<Vec<ProcessIdentity>> {
    Ok(snapshot_observed()?
        .into_iter()
        .map(|process| process.identity)
        .collect())
}

pub fn snapshot_observed() -> Result<Vec<ObservedProcess>> {
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    ensure!(
        raw != INVALID_HANDLE_VALUE,
        "프로세스 스냅숏 실패: {}",
        std::io::Error::last_os_error()
    );
    let handle = OwnedHandle(raw);
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut result = Vec::new();
    let mut available = unsafe { Process32FirstW(handle.0, &mut entry) };
    while available != 0 {
        match observe(entry.th32ProcessID, entry.th32ParentProcessID) {
            Ok(identity) => result.push(identity),
            Err(error) => {
                tracing::debug!(pid = entry.th32ProcessID, %error, "조회할 수 없는 프로세스")
            }
        }
        available = unsafe { Process32NextW(handle.0, &mut entry) };
    }
    let error = std::io::Error::last_os_error();
    ensure!(
        error.raw_os_error() == Some(18),
        "프로세스 열거 중 오류: {error}"
    );
    Ok(result)
}
