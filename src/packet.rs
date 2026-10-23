//! 길이를 검증한 IP·TCP·UDP 파싱, 주소 변환과 인터넷 체크섬을 구현한다.
//! 조각화된 패킷은 포트를 추측하지 않고 상위의 차단 정책으로 돌려보낸다.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacketError {
    #[error("패킷이 잘렸거나 헤더 길이가 잘못됐습니다")]
    Length,
    #[error("지원하지 않는 IP 버전 또는 전송 프로토콜입니다")]
    Unsupported,
    #[error("조각화된 패킷은 재조립 전 변환할 수 없습니다")]
    Fragment,
    #[error("주소군이 일치하지 않습니다")]
    AddressFamily,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Protocol {
    Tcp = 6,
    Udp = 17,
}

impl TryFrom<u8> for Protocol {
    type Error = PacketError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            6 => Ok(Self::Tcp),
            17 => Ok(Self::Udp),
            _ => Err(PacketError::Unsupported),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketMeta {
    pub protocol: Protocol,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub transport: usize,
    pub payload: usize,
    pub length: usize,
    pub ipv6: bool,
}

fn word(bytes: &[u8], offset: usize) -> Result<u16, PacketError> {
    let data = bytes.get(offset..offset + 2).ok_or(PacketError::Length)?;
    Ok(u16::from_be_bytes([data[0], data[1]]))
}

pub fn parse(bytes: &[u8]) -> Result<PacketMeta, PacketError> {
    let version = bytes.first().ok_or(PacketError::Length)? >> 4;
    let (source, destination, mut protocol, mut transport, length) = match version {
        4 => {
            if bytes.len() < 20 {
                return Err(PacketError::Length);
            }
            let header = usize::from(bytes[0] & 15) * 4;
            let length = usize::from(word(bytes, 2)?);
            if header < 20 || length < header || bytes.len() != length {
                return Err(PacketError::Length);
            }
            if word(bytes, 6)? & 0x3fff != 0 {
                return Err(PacketError::Fragment);
            }
            (
                IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
                IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
                bytes[9],
                header,
                length,
            )
        }
        6 => {
            if bytes.len() < 40 {
                return Err(PacketError::Length);
            }
            let length = 40 + usize::from(word(bytes, 4)?);
            if bytes.len() != length {
                return Err(PacketError::Length);
            }
            let source = Ipv6Addr::from(
                <[u8; 16]>::try_from(&bytes[8..24]).map_err(|_| PacketError::Length)?,
            );
            let destination = Ipv6Addr::from(
                <[u8; 16]>::try_from(&bytes[24..40]).map_err(|_| PacketError::Length)?,
            );
            (
                IpAddr::V6(source),
                IpAddr::V6(destination),
                bytes[6],
                40,
                length,
            )
        }
        _ => return Err(PacketError::Unsupported),
    };
    if version == 6 {
        // 확장 헤더의 반복 횟수와 각 길이를 제한해 순환·과대 입력을 거부한다.
        for _ in 0..16 {
            match protocol {
                0 | 43 | 60 => {
                    let extension = bytes
                        .get(transport..transport + 2)
                        .ok_or(PacketError::Length)?;
                    let next = extension[0];
                    let size = (usize::from(extension[1]) + 1) * 8;
                    transport = transport.checked_add(size).ok_or(PacketError::Length)?;
                    if transport > length {
                        return Err(PacketError::Length);
                    }
                    protocol = next;
                }
                44 => return Err(PacketError::Fragment),
                _ => break,
            }
        }
    }
    let protocol = Protocol::try_from(protocol)?;
    let minimum = match protocol {
        Protocol::Tcp => 20,
        Protocol::Udp => 8,
    };
    if transport + minimum > length {
        return Err(PacketError::Length);
    }
    let payload = match protocol {
        Protocol::Tcp => {
            let size = usize::from(bytes[transport + 12] >> 4) * 4;
            if size < 20 || transport + size > length {
                return Err(PacketError::Length);
            }
            transport + size
        }
        Protocol::Udp => {
            if usize::from(word(bytes, transport + 4)?) != length - transport {
                return Err(PacketError::Length);
            }
            transport + 8
        }
    };
    Ok(PacketMeta {
        protocol,
        source: SocketAddr::new(source, word(bytes, transport)?),
        destination: SocketAddr::new(destination, word(bytes, transport + 2)?),
        transport,
        payload,
        length,
        ipv6: version == 6,
    })
}

fn accumulate(mut sum: u64, bytes: &[u8]) -> u64 {
    let (pairs, remainder) = bytes.as_chunks::<2>();
    for pair in pairs {
        sum += u64::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let Some(last) = remainder.first() {
        sum += u64::from(*last) << 8;
    }
    sum
}

fn finish(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn checksum(bytes: &[u8]) -> u16 {
    finish(accumulate(0, bytes))
}

fn pseudo_sum(meta: &PacketMeta) -> u64 {
    let length = (meta.length - meta.transport) as u32;
    let mut sum = 0;
    match (meta.source.ip(), meta.destination.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            sum = accumulate(sum, &source.octets());
            sum = accumulate(sum, &destination.octets());
            sum += u64::from(length);
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            sum = accumulate(sum, &source.octets());
            sum = accumulate(sum, &destination.octets());
            sum = accumulate(sum, &length.to_be_bytes());
        }
        _ => unreachable!("파싱된 IP 패킷의 주소군은 같습니다"),
    }
    sum + u64::from(meta.protocol as u8)
}

pub fn recalculate(bytes: &mut [u8]) -> Result<(), PacketError> {
    let meta = parse(bytes)?;
    if !meta.ipv6 {
        bytes[10..12].fill(0);
        let value = checksum(&bytes[..meta.transport]);
        bytes[10..12].copy_from_slice(&value.to_be_bytes());
    }
    let offset = meta.transport
        + match meta.protocol {
            Protocol::Tcp => 16,
            Protocol::Udp => 6,
        };
    bytes[offset..offset + 2].fill(0);
    let mut value = finish(accumulate(pseudo_sum(&meta), &bytes[meta.transport..]));
    if meta.protocol == Protocol::Udp && value == 0 {
        value = 0xffff;
    }
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

pub fn checksums_valid(bytes: &[u8]) -> Result<bool, PacketError> {
    let meta = parse(bytes)?;
    if meta.ipv6 && meta.protocol == Protocol::Udp && word(bytes, meta.transport + 6)? == 0 {
        return Ok(false);
    }
    let ip_valid = meta.ipv6 || checksum(&bytes[..meta.transport]) == 0;
    let udp_disabled =
        !meta.ipv6 && meta.protocol == Protocol::Udp && word(bytes, meta.transport + 6)? == 0;
    Ok(ip_valid
        && (udp_disabled || finish(accumulate(pseudo_sum(&meta), &bytes[meta.transport..])) == 0))
}

pub fn rewrite(
    bytes: &mut [u8],
    source: SocketAddr,
    destination: SocketAddr,
) -> Result<(), PacketError> {
    let meta = parse(bytes)?;
    match (source.ip(), destination.ip(), meta.ipv6) {
        (IpAddr::V4(source), IpAddr::V4(destination), false) => {
            bytes[12..16].copy_from_slice(&source.octets());
            bytes[16..20].copy_from_slice(&destination.octets());
        }
        (IpAddr::V6(source), IpAddr::V6(destination), true) => {
            bytes[8..24].copy_from_slice(&source.octets());
            bytes[24..40].copy_from_slice(&destination.octets());
        }
        _ => return Err(PacketError::AddressFamily),
    }
    bytes[meta.transport..meta.transport + 2].copy_from_slice(&source.port().to_be_bytes());
    bytes[meta.transport + 2..meta.transport + 4]
        .copy_from_slice(&destination.port().to_be_bytes());
    recalculate(bytes)
}

fn ip_header(
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    payload_len: usize,
) -> Result<Vec<u8>, PacketError> {
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let length = u16::try_from(20 + payload_len).map_err(|_| PacketError::Length)?;
            let mut bytes = vec![0; 20 + payload_len];
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&length.to_be_bytes());
            bytes[6] = 0x40;
            bytes[8] = 64;
            bytes[9] = protocol;
            bytes[12..16].copy_from_slice(&source.octets());
            bytes[16..20].copy_from_slice(&destination.octets());
            Ok(bytes)
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let length = u16::try_from(payload_len).map_err(|_| PacketError::Length)?;
            let mut bytes = vec![0; 40 + payload_len];
            bytes[0] = 0x60;
            bytes[4..6].copy_from_slice(&length.to_be_bytes());
            bytes[6] = protocol;
            bytes[7] = 64;
            bytes[8..24].copy_from_slice(&source.octets());
            bytes[24..40].copy_from_slice(&destination.octets());
            Ok(bytes)
        }
        _ => Err(PacketError::AddressFamily),
    }
}

pub fn udp(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, PacketError> {
    let size = u16::try_from(8 + payload.len()).map_err(|_| PacketError::Length)?;
    let mut bytes = ip_header(source.ip(), destination.ip(), 17, usize::from(size))?;
    let start = if source.is_ipv4() { 20 } else { 40 };
    bytes[start..start + 2].copy_from_slice(&source.port().to_be_bytes());
    bytes[start + 2..start + 4].copy_from_slice(&destination.port().to_be_bytes());
    bytes[start + 4..start + 6].copy_from_slice(&size.to_be_bytes());
    bytes[start + 8..].copy_from_slice(payload);
    recalculate(&mut bytes)?;
    Ok(bytes)
}

pub fn tcp_reset(original: &[u8]) -> Result<Option<Vec<u8>>, PacketError> {
    let meta = parse(original)?;
    if meta.protocol != Protocol::Tcp {
        return Err(PacketError::Unsupported);
    }
    let flags = original[meta.transport + 13];
    if flags & 4 != 0 {
        return Ok(None);
    }
    let mut bytes = ip_header(meta.destination.ip(), meta.source.ip(), 6, 20)?;
    let start = if meta.ipv6 { 40 } else { 20 };
    bytes[start..start + 2].copy_from_slice(&meta.destination.port().to_be_bytes());
    bytes[start + 2..start + 4].copy_from_slice(&meta.source.port().to_be_bytes());
    bytes[start + 12] = 0x50;
    if flags & 0x10 != 0 {
        bytes[start + 4..start + 8]
            .copy_from_slice(&original[meta.transport + 8..meta.transport + 12]);
        bytes[start + 13] = 4;
    } else {
        let sequence = u32::from_be_bytes(
            original[meta.transport + 4..meta.transport + 8]
                .try_into()
                .map_err(|_| PacketError::Length)?,
        );
        let amount = (meta.length - meta.payload) as u32
            + u32::from(flags & 2 != 0)
            + u32::from(flags & 1 != 0);
        bytes[start + 8..start + 12].copy_from_slice(&sequence.wrapping_add(amount).to_be_bytes());
        bytes[start + 13] = 0x14;
    }
    recalculate(&mut bytes)?;
    Ok(Some(bytes))
}

pub fn udp_unreachable(original: &[u8]) -> Result<Vec<u8>, PacketError> {
    let meta = parse(original)?;
    if meta.protocol != Protocol::Udp {
        return Err(PacketError::Unsupported);
    }
    let quote = original.len().min(if meta.ipv6 { 1232 } else { 548 });
    let protocol = if meta.ipv6 { 58 } else { 1 };
    let mut bytes = ip_header(meta.destination.ip(), meta.source.ip(), protocol, 8 + quote)?;
    let start = if meta.ipv6 { 40 } else { 20 };
    bytes[start] = if meta.ipv6 { 1 } else { 3 };
    bytes[start + 1] = if meta.ipv6 { 1 } else { 13 };
    bytes[start + 8..].copy_from_slice(&original[..quote]);
    let sum = if meta.ipv6 {
        let mut sum = accumulate(0, &bytes[8..40]);
        sum = accumulate(sum, &((bytes.len() - 40) as u32).to_be_bytes());
        sum + 58
    } else {
        0
    };
    let value = finish(accumulate(sum, &bytes[start..]));
    bytes[start + 2..start + 4].copy_from_slice(&value.to_be_bytes());
    if !meta.ipv6 {
        let value = checksum(&bytes[..20]);
        bytes[10..12].copy_from_slice(&value.to_be_bytes());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internet_checksum_matches_rfc_1071_example() {
        assert_eq!(checksum(&[0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7]), 0x220d);
    }

    #[test]
    fn udp_computed_zero_is_transmitted_as_all_ones() {
        // 의사 헤더와 UDP 헤더의 합 0x142b를 보완하는 페이로드이다.
        let bytes = udp(
            "10.0.0.1:1".parse().unwrap(),
            "10.0.0.2:2".parse().unwrap(),
            &[0xeb, 0xd4],
        )
        .unwrap();
        assert_eq!(&bytes[26..28], &[0xff, 0xff]);
        assert!(checksums_valid(&bytes).unwrap());
    }

    #[test]
    fn ipv6_udp_zero_field_is_invalid_even_when_sum_would_match() {
        let mut bytes = udp(
            "[2001:db8::1]:1".parse().unwrap(),
            "[2001:db8::2]:2".parse().unwrap(),
            &[0xa4, 0x62],
        )
        .unwrap();
        assert_eq!(&bytes[46..48], &[0xff, 0xff]);
        bytes[46..48].fill(0);
        assert!(!checksums_valid(&bytes).unwrap());
    }
}
