//! WinDivert 2.2의 C ABI를 동적 로딩한다. 시스템 폴더로 파일을 복사하지 않는다.

use crate::paths::AppPaths;
use anyhow::{Context, Result, ensure};
use libloading::Library;
use std::{
    ffi::{CStr, CString, c_char, c_void},
    net::{IpAddr, Ipv6Addr},
    sync::Arc,
};
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    pub timestamp: i64,
    pub bits: u32,
    pub reserved: u32,
    pub data: [u8; 64],
}
impl Default for Address {
    fn default() -> Self {
        Self {
            timestamp: 0,
            bits: 0,
            reserved: 0,
            data: [0; 64],
        }
    }
}
const _: () = assert!(std::mem::size_of::<Address>() == 80);

impl Address {
    pub fn network_path(&self) -> crate::packet_router::NetworkPath {
        crate::packet_router::NetworkPath {
            interface: u32::from_ne_bytes(self.data[..4].try_into().expect("고정 길이")),
            sub_interface: u32::from_ne_bytes(self.data[4..8].try_into().expect("고정 길이")),
        }
    }
    pub fn set_network_path(&mut self, path: crate::packet_router::NetworkPath) {
        self.data[..4].copy_from_slice(&path.interface.to_ne_bytes());
        self.data[4..8].copy_from_slice(&path.sub_interface.to_ne_bytes());
    }
    pub fn event(&self) -> u8 {
        (self.bits >> 8) as u8
    }
    pub fn outbound(&self) -> bool {
        self.bits & (1 << 17) != 0
    }
    pub fn loopback(&self) -> bool {
        self.bits & (1 << 18) != 0
    }
    pub fn set_outbound(&mut self, outbound: bool) {
        self.bits = (self.bits & !(1 << 17)) | (u32::from(outbound) << 17);
    }
    pub fn socket(&self) -> Result<SocketData> {
        ensure!(self.bits & 255 == 3, "소켓 계층 주소가 아닙니다");
        // 공식 구조체의 64바이트 영역을 정렬되지 않은 읽기로 복사한다.
        Ok(unsafe { std::ptr::read_unaligned(self.data.as_ptr().cast::<SocketData>()) })
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SocketData {
    pub endpoint_id: u64,
    pub parent_endpoint_id: u64,
    pub process_id: u32,
    pub local_addr: [u32; 4],
    pub remote_addr: [u32; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: u8,
}
const _: () = assert!(std::mem::size_of::<SocketData>() == 64);

pub fn decode_ip(words: [u32; 4]) -> IpAddr {
    let mut bytes = [0; 16];
    for (chunk, word) in bytes
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(words.into_iter().rev())
    {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    let ip = Ipv6Addr::from(bytes);
    ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4)
}

type OpenFn = unsafe extern "C" fn(*const c_char, i32, i16, u64) -> HANDLE;
type RecvFn = unsafe extern "C" fn(HANDLE, *mut c_void, u32, *mut u32, *mut Address) -> i32;
type SendFn = unsafe extern "C" fn(HANDLE, *const c_void, u32, *mut u32, *const Address) -> i32;
type CloseFn = unsafe extern "C" fn(HANDLE) -> i32;
type ShutdownFn = unsafe extern "C" fn(HANDLE, i32) -> i32;
type CalcFn = unsafe extern "C" fn(*mut c_void, u32, *mut Address, u64) -> i32;
type GetParamFn = unsafe extern "C" fn(HANDLE, i32, *mut u64) -> i32;
type CompileFn =
    unsafe extern "C" fn(*const c_char, i32, *mut c_char, u32, *mut *const c_char, *mut u32) -> i32;
type EvalFn = unsafe extern "C" fn(*const c_char, *const c_void, u32, *const Address) -> i32;

pub struct DivertApi {
    _library: Library,
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    close: CloseFn,
    shutdown: ShutdownFn,
    calc: CalcFn,
    get_param: GetParamFn,
    compile: CompileFn,
    evaluate: EvalFn,
}

impl DivertApi {
    pub fn load(paths: &AppPaths) -> Result<Arc<Self>> {
        ensure!(
            cfg!(target_arch = "x86_64"),
            "x64 WinDivert 배포만 지원합니다"
        );
        let dll = paths.resolve("bin/WinDivert.dll")?;
        let driver = paths.resolve("bin/WinDivert64.sys")?;
        ensure!(
            dll.is_file() && driver.is_file(),
            "bin에 공식 WinDivert.dll과 WinDivert64.sys가 필요합니다"
        );
        // 의존 DLL 검색은 지정한 DLL 디렉터리와 Windows 시스템 디렉터리로 제한한다.
        let library: Library =
            unsafe { libloading::os::windows::Library::load_with_flags(&dll, 0x100 | 0x800)? }
                .into();
        // 심볼은 라이브러리를 구조체에 보유하는 동안 유효하며 공식 C 선언과 일치한다.
        unsafe {
            Ok(Arc::new(Self {
                open: *library.get(b"WinDivertOpen\0")?,
                recv: *library.get(b"WinDivertRecv\0")?,
                send: *library.get(b"WinDivertSend\0")?,
                close: *library.get(b"WinDivertClose\0")?,
                shutdown: *library.get(b"WinDivertShutdown\0")?,
                calc: *library.get(b"WinDivertHelperCalcChecksums\0")?,
                get_param: *library.get(b"WinDivertGetParam\0")?,
                compile: *library.get(b"WinDivertHelperCompileFilter\0")?,
                evaluate: *library.get(b"WinDivertHelperEvalFilter\0")?,
                _library: library,
            }))
        }
    }
    /// 커널 핸들을 열기 전에 계층별 필터 문법을 실제 DLL로 검증한다.
    pub fn validate_filter(&self, filter: &str, layer: i32) -> Result<()> {
        let filter = CString::new(filter)?;
        let mut description = std::ptr::null();
        let mut position = 0;
        let valid = unsafe {
            (self.compile)(
                filter.as_ptr(),
                layer,
                std::ptr::null_mut(),
                0,
                &mut description,
                &mut position,
            )
        };
        if valid == 0 {
            // 공식 API는 오류 문자열을 해제할 필요가 없는 정적 C 문자열로 반환한다.
            let message = if description.is_null() {
                "설명 없음".into()
            } else {
                unsafe { CStr::from_ptr(description) }.to_string_lossy()
            };
            anyhow::bail!("WinDivert 필터 오류, 위치 {position}: {message}");
        }
        Ok(())
    }
    pub fn matches(&self, filter: &str, packet: &[u8], address: &Address) -> Result<bool> {
        let filter = CString::new(filter)?;
        let result = unsafe {
            (self.evaluate)(
                filter.as_ptr(),
                packet.as_ptr().cast(),
                u32::try_from(packet.len())?,
                address,
            )
        };
        if result == 0 {
            let error = std::io::Error::last_os_error();
            ensure!(error.raw_os_error() == Some(0), "필터 평가 실패: {error}");
        }
        Ok(result != 0)
    }
    pub fn recalculate(&self, packet: &mut [u8], address: &mut Address) -> Result<()> {
        ensure!(
            unsafe {
                (self.calc)(
                    packet.as_mut_ptr().cast(),
                    u32::try_from(packet.len())?,
                    address,
                    0,
                )
            } != 0,
            "WinDivert 체크섬 계산 실패"
        );
        Ok(())
    }
    pub fn open(
        self: &Arc<Self>,
        filter: &str,
        layer: i32,
        priority: i16,
        flags: u64,
    ) -> Result<DivertHandle> {
        self.validate_filter(filter, layer)?;
        let filter = CString::new(filter)?;
        // 필터 문자열은 호출이 끝날 때까지 유효하다.
        let raw = unsafe { (self.open)(filter.as_ptr(), layer, priority, flags) };
        if raw == INVALID_HANDLE_VALUE || raw.is_null() {
            return Err(std::io::Error::last_os_error()).context("WinDivertOpen 실패");
        }
        let handle = DivertHandle {
            api: Arc::clone(self),
            raw,
        };
        let (major, minor) = (handle.parameter(3)?, handle.parameter(4)?);
        ensure!(
            major == 2 && minor >= 2,
            "WinDivert 2.2 이상 2.x가 필요합니다"
        );
        Ok(handle)
    }
}

pub struct DivertHandle {
    api: Arc<DivertApi>,
    raw: HANDLE,
}
// WinDivert는 동일 핸들에 대한 병렬 수신·송신·종료를 지원한다. 소유권은 한 번만 해제된다.
unsafe impl Send for DivertHandle {}
unsafe impl Sync for DivertHandle {}
impl DivertHandle {
    pub fn parameter(&self, name: i32) -> Result<u64> {
        let mut value = 0;
        ensure!(
            unsafe { (self.api.get_param)(self.raw, name, &mut value) } != 0,
            "WinDivertGetParam 실패: {}",
            std::io::Error::last_os_error()
        );
        Ok(value)
    }
    pub fn receive(&self, buffer: &mut [u8]) -> Result<(usize, Address)> {
        let mut length = 0;
        let mut address = Address::default();
        let ptr = if buffer.is_empty() {
            std::ptr::null_mut()
        } else {
            buffer.as_mut_ptr().cast()
        };
        let received = unsafe {
            (self.api.recv)(
                self.raw,
                ptr,
                u32::try_from(buffer.len())?,
                &mut length,
                &mut address,
            )
        };
        if received == 0 {
            return Err(std::io::Error::last_os_error()).context("WinDivertRecv 실패");
        }
        ensure!(
            length as usize <= buffer.len(),
            "WinDivert 수신 길이가 버퍼를 초과했습니다"
        );
        Ok((length as usize, address))
    }
    pub fn recalculate(&self, packet: &mut [u8], address: &mut Address) -> Result<()> {
        self.api.recalculate(packet, address)
    }
    pub fn send(&self, packet: &[u8], address: &Address) -> Result<()> {
        let mut sent = 0;
        ensure!(
            unsafe {
                (self.api.send)(
                    self.raw,
                    packet.as_ptr().cast(),
                    u32::try_from(packet.len())?,
                    &mut sent,
                    address,
                )
            } != 0,
            "WinDivertSend 실패: {}",
            std::io::Error::last_os_error()
        );
        ensure!(
            sent as usize == packet.len(),
            "WinDivert 패킷이 일부만 송신됐습니다"
        );
        Ok(())
    }
    pub fn shutdown(&self) -> Result<()> {
        ensure!(
            unsafe { (self.api.shutdown)(self.raw, 3) } != 0,
            "WinDivertShutdown 실패: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
    pub fn observe_sockets(api: &Arc<DivertApi>) -> Result<Self> {
        api.open("true", 3, 0, 0x1 | 0x4)
            .context("소켓 관찰 핸들 열기 실패")
    }
}
impl Drop for DivertHandle {
    fn drop(&mut self) {
        unsafe {
            (self.api.close)(self.raw);
        }
    }
}
