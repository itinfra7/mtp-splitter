//! IP Helper로 시작 전부터 존재한 IPv4/IPv6 TCP·UDP 소켓의 PID를 읽는다.
//! 행의 신원 확인과 스냅숏 수명은 감시기가 관리하며 PID 0은 소유권 증거로 쓰지 않는다.

use crate::{packet::Protocol, process_tracker::SocketKey};
use anyhow::{Context, Result, ensure};
use std::{
    ffi::c_void,
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use windows_sys::Win32::{Foundation::ERROR_INSUFFICIENT_BUFFER, NetworkManagement::IpHelper::*};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketRecord {
    pub key: SocketKey,
    pub pid: u32,
}

/// 동시 소켓 생성에 따른 크기 증가를 제한 횟수만큼 재시도한다.
fn table<T: Copy>(
    offset: usize,
    mut query: impl FnMut(*mut c_void, &mut u32) -> u32,
) -> Result<Vec<T>> {
    let mut capacity = 4096usize;
    for _ in 0..8 {
        ensure!(
            (4..=32 * 1024 * 1024).contains(&capacity),
            "IP Helper 테이블 크기 한도 초과"
        );
        let mut storage = vec![0u64; capacity.div_ceil(8)];
        let mut size = u32::try_from(capacity)?;
        let status = query(storage.as_mut_ptr().cast(), &mut size);
        if status == ERROR_INSUFFICIENT_BUFFER {
            capacity = (size as usize).max(capacity.saturating_mul(2));
            continue;
        }
        ensure!(
            status == 0,
            "IP Helper 조회 실패: {}",
            std::io::Error::from_raw_os_error(status as i32)
        );
        let length = size as usize;
        ensure!(
            length >= offset && length <= capacity,
            "IP Helper 응답 길이가 잘못됐습니다"
        );
        let count = unsafe { std::ptr::read_unaligned(storage.as_ptr().cast::<u32>()) } as usize;
        let bytes = count
            .checked_mul(size_of::<T>())
            .and_then(|bytes| offset.checked_add(bytes))
            .context("IP Helper 행 수 오버플로")?;
        ensure!(bytes <= length, "IP Helper 행 수가 응답 길이를 초과합니다");
        let base = unsafe { storage.as_ptr().cast::<u8>().add(offset) };
        let mut rows = Vec::with_capacity(count);
        for index in 0..count {
            // 공식 repr(C) 행 크기와 테이블의 실제 멤버 오프셋을 사용한다.
            rows.push(unsafe {
                std::ptr::read_unaligned(base.add(index * size_of::<T>()).cast::<T>())
            });
        }
        return Ok(rows);
    }
    anyhow::bail!("IP Helper 테이블 크기가 반복해서 바뀌었습니다")
}

fn port(raw: u32) -> u16 {
    u16::from_be(raw as u16)
}
fn ipv6(raw: [u8; 16]) -> IpAddr {
    let ip = Ipv6Addr::from(raw);
    ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4)
}

pub fn snapshot() -> Result<Vec<SocketRecord>> {
    let tcp4 = table::<MIB_TCPROW_OWNER_PID>(
        offset_of!(MIB_TCPTABLE_OWNER_PID, table),
        |buffer, size| unsafe {
            GetExtendedTcpTable(buffer, size, 0, 2, TCP_TABLE_OWNER_PID_ALL, 0)
        },
    )?;
    let tcp6 = table::<MIB_TCP6ROW_OWNER_PID>(
        offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
        |buffer, size| unsafe {
            GetExtendedTcpTable(buffer, size, 0, 23, TCP_TABLE_OWNER_PID_ALL, 0)
        },
    )?;
    let udp4 = table::<MIB_UDPROW_OWNER_PID>(
        offset_of!(MIB_UDPTABLE_OWNER_PID, table),
        |buffer, size| unsafe { GetExtendedUdpTable(buffer, size, 0, 2, UDP_TABLE_OWNER_PID, 0) },
    )?;
    let udp6 = table::<MIB_UDP6ROW_OWNER_PID>(
        offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
        |buffer, size| unsafe { GetExtendedUdpTable(buffer, size, 0, 23, UDP_TABLE_OWNER_PID, 0) },
    )?;
    let mut records = Vec::new();
    let mut append = |protocol, ip, raw_port, pid| {
        let port = port(raw_port);
        if port != 0 && pid != 0 {
            records.push(SocketRecord {
                key: SocketKey {
                    protocol,
                    local: SocketAddr::new(ip, port),
                },
                pid,
            });
        }
    };
    for row in tcp4 {
        append(
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
            row.dwLocalPort,
            row.dwOwningPid,
        );
    }
    for row in tcp6 {
        append(
            Protocol::Tcp,
            ipv6(row.ucLocalAddr),
            row.dwLocalPort,
            row.dwOwningPid,
        );
    }
    for row in udp4 {
        append(
            Protocol::Udp,
            IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
            row.dwLocalPort,
            row.dwOwningPid,
        );
    }
    for row in udp6 {
        append(
            Protocol::Udp,
            ipv6(row.ucLocalAddr),
            row.dwLocalPort,
            row.dwOwningPid,
        );
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn table_retries_growth_and_checks_row_count_before_reading() {
        let mut attempts = 0;
        let rows = table::<u32>(4, |buffer, length| {
            attempts += 1;
            if attempts == 1 {
                *length = 8192;
                return ERROR_INSUFFICIENT_BUFFER;
            }
            let words = buffer.cast::<u32>();
            unsafe {
                words.write(2);
                words.add(1).write(11);
                words.add(2).write(22);
            }
            *length = 12;
            0
        })
        .unwrap();
        assert_eq!(rows, [11, 22]);
        assert_eq!(attempts, 2);
        assert!(
            table::<u32>(4, |buffer, length| {
                unsafe {
                    buffer.cast::<u32>().write(99);
                }
                *length = 4;
                0
            })
            .is_err()
        );
    }
    #[test]
    fn table_growth_and_os_failures_are_bounded() {
        assert!(
            table::<u32>(4, |_, size| {
                *size = u32::MAX;
                ERROR_INSUFFICIENT_BUFFER
            })
            .is_err()
        );
        assert!(table::<u32>(4, |_, _| 5).is_err());
        assert_eq!(port(u32::from(53u16.to_be())), 53);
        assert_eq!(
            ipv6("::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap().octets()),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }
}
