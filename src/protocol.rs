//! 전용 게이트웨이와 공유할 길이가 명시된 다중화 프레임을 정의한다.
//! 이 프로토콜은 일반 Telegram MTProxy의 중계 기능이 아니다.

use crate::fake_dns::normalize_domain;
use anyhow::{Result, bail, ensure};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub const VERSION: u8 = 1;
pub const MAX_FRAME: usize = 262144;
pub const MAX_TCP_DATA: usize = 16384;
pub const MAX_DATAGRAM: usize = 65507;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    Cancelled = 0,
    General = 1,
    Policy = 2,
    Network = 3,
    Host = 4,
    Refused = 5,
    Timeout = 6,
    Unsupported = 7,
    Address = 8,
    Capacity = 9,
    Protocol = 10,
}
impl TryFrom<u16> for ErrorCode {
    type Error = anyhow::Error;
    fn try_from(value: u16) -> Result<Self> {
        match value {
            0 => Ok(Self::Cancelled),
            1 => Ok(Self::General),
            2 => Ok(Self::Policy),
            3 => Ok(Self::Network),
            4 => Ok(Self::Host),
            5 => Ok(Self::Refused),
            6 => Ok(Self::Timeout),
            7 => Ok(Self::Unsupported),
            8 => Ok(Self::Address),
            9 => Ok(Self::Capacity),
            10 => Ok(Self::Protocol),
            _ => bail!("알 수 없는 오류 코드입니다"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorMessage {
    pub code: ErrorCode,
    pub message: String,
}
impl ErrorMessage {
    pub fn new(code: ErrorCode, message: &str) -> Self {
        let mut end = message.len().min(256);
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        Self {
            code,
            message: message[..end].to_owned(),
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(self.message.len() <= 256, "오류 문자열이 너무 깁니다");
        let mut bytes = (self.code as u16).to_be_bytes().to_vec();
        bytes.extend_from_slice(&(self.message.len() as u16).to_be_bytes());
        bytes.extend_from_slice(self.message.as_bytes());
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            (4..=260).contains(&bytes.len()),
            "오류 본문 길이가 잘못됐습니다"
        );
        let code = ErrorCode::try_from(u16::from_be_bytes([bytes[0], bytes[1]]))?;
        let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        ensure!(length + 4 == bytes.len(), "오류 문자열 길이가 잘못됐습니다");
        Ok(Self {
            code,
            message: std::str::from_utf8(&bytes[4..])?.to_owned(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetAddress {
    Ip(IpAddr),
    Domain(String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub address: TargetAddress,
    pub port: u16,
}
impl Target {
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(self.port != 0, "목적지 포트가 0입니다");
        let mut output = Vec::new();
        match &self.address {
            TargetAddress::Ip(IpAddr::V4(ip)) => {
                output.push(1);
                output.extend_from_slice(&ip.octets());
            }
            TargetAddress::Ip(IpAddr::V6(ip)) => {
                output.push(4);
                output.extend_from_slice(&ip.octets());
            }
            TargetAddress::Domain(domain) => {
                let domain = normalize_domain(domain)?;
                output.extend_from_slice(&[3, u8::try_from(domain.len())?]);
                output.extend_from_slice(domain.as_bytes());
            }
        }
        output.extend_from_slice(&self.port.to_be_bytes());
        Ok(output)
    }
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize)> {
        let kind = *bytes
            .first()
            .ok_or_else(|| anyhow::anyhow!("목적지 주소가 없습니다"))?;
        let (address, cursor) = match kind {
            1 => {
                ensure!(bytes.len() >= 7, "IPv4 목적지가 잘렸습니다");
                (
                    TargetAddress::Ip(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(
                        &bytes[1..5],
                    )?))),
                    5,
                )
            }
            4 => {
                ensure!(bytes.len() >= 19, "IPv6 목적지가 잘렸습니다");
                (
                    TargetAddress::Ip(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(
                        &bytes[1..17],
                    )?))),
                    17,
                )
            }
            3 => {
                ensure!(bytes.len() >= 2, "도메인 길이가 없습니다");
                let length = usize::from(bytes[1]);
                ensure!(bytes.len() >= 4 + length, "도메인 목적지가 잘렸습니다");
                (
                    TargetAddress::Domain(normalize_domain(std::str::from_utf8(
                        &bytes[2..2 + length],
                    )?)?),
                    2 + length,
                )
            }
            _ => bail!("알 수 없는 목적지 주소 유형입니다"),
        };
        let port = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
        ensure!(port != 0, "목적지 포트가 0입니다");
        Ok((Self { address, port }, cursor + 2))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Hello = 1,
    Welcome = 2,
    OpenTcp = 0x10,
    OpenUdp = 0x11,
    OpenOk = 0x12,
    OpenError = 0x13,
    TcpData = 0x20,
    UdpDatagram = 0x21,
    TcpFin = 0x22,
    StreamReset = 0x23,
    WindowUpdate = 0x30,
    Ping = 0x31,
    Pong = 0x32,
    GoAway = 0x33,
    DnsQuery = 0x40,
    DnsResponse = 0x41,
}
impl TryFrom<u8> for FrameType {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Welcome),
            0x10 => Ok(Self::OpenTcp),
            0x11 => Ok(Self::OpenUdp),
            0x12 => Ok(Self::OpenOk),
            0x13 => Ok(Self::OpenError),
            0x20 => Ok(Self::TcpData),
            0x21 => Ok(Self::UdpDatagram),
            0x22 => Ok(Self::TcpFin),
            0x23 => Ok(Self::StreamReset),
            0x30 => Ok(Self::WindowUpdate),
            0x31 => Ok(Self::Ping),
            0x32 => Ok(Self::Pong),
            0x33 => Ok(Self::GoAway),
            0x40 => Ok(Self::DnsQuery),
            0x41 => Ok(Self::DnsResponse),
            _ => bail!("알 수 없는 프레임 종류입니다"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameType,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}
impl Frame {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.payload.len() <= MAX_FRAME - 8, "프레임 크기 한도 초과");
        let control = matches!(
            self.kind,
            FrameType::Hello
                | FrameType::Welcome
                | FrameType::Ping
                | FrameType::Pong
                | FrameType::GoAway
        );
        if control {
            ensure!(
                self.stream_id == 0,
                "제어 프레임의 스트림 ID는 0이어야 합니다"
            );
        } else if self.kind != FrameType::WindowUpdate {
            ensure!(
                self.stream_id != 0 && self.stream_id & 1 == 1,
                "스트림 ID는 양의 홀수여야 합니다"
            );
        }
        match self.kind {
            FrameType::OpenTcp | FrameType::OpenUdp => {
                let (_, length) = Target::decode(&self.payload)?;
                ensure!(
                    length == self.payload.len(),
                    "목적지 뒤에 불필요한 데이터가 있습니다"
                );
            }
            FrameType::OpenOk => {
                let (local, length) = Target::decode(&self.payload)?;
                let (peer, second) = Target::decode(&self.payload[length..])?;
                ensure!(
                    length + second == self.payload.len()
                        && matches!(local.address, TargetAddress::Ip(_))
                        && matches!(peer.address, TargetAddress::Ip(_)),
                    "OPEN_OK endpoint가 잘못됐습니다"
                );
            }
            FrameType::TcpData => ensure!(
                !self.payload.is_empty() && self.payload.len() <= MAX_TCP_DATA,
                "TCP 데이터 길이가 잘못됐습니다"
            ),
            FrameType::UdpDatagram => ensure!(
                self.payload.len() <= MAX_DATAGRAM,
                "UDP 데이터그램이 너무 큽니다"
            ),
            FrameType::TcpFin => ensure!(self.payload.is_empty(), "FIN 본문이 비어 있지 않습니다"),
            FrameType::Ping | FrameType::Pong => {
                ensure!(self.payload.len() == 8, "PING/PONG 길이가 잘못됐습니다")
            }
            FrameType::WindowUpdate => {
                ensure!(
                    self.stream_id == 0 || self.stream_id & 1 == 1,
                    "윈도 갱신의 스트림 ID가 잘못됐습니다"
                );
                ensure!(self.payload.len() == 4, "윈도 갱신 길이가 잘못됐습니다");
                let credit = u32::from_be_bytes(self.payload[..4].try_into()?);
                ensure!(
                    credit > 0 && credit <= 0x7fff_ffff,
                    "윈도 크레딧이 잘못됐습니다"
                );
            }
            FrameType::Hello | FrameType::Welcome => {
                Settings::decode(&self.payload)?;
            }
            FrameType::OpenError | FrameType::StreamReset | FrameType::GoAway => {
                ErrorMessage::decode(&self.payload)?;
            }
            FrameType::DnsQuery | FrameType::DnsResponse => ensure!(
                (12..=65535).contains(&self.payload.len()),
                "DNS wire 메시지 길이가 잘못됐습니다"
            ),
        }
        Ok(())
    }
    pub fn write(&self, writer: &mut impl Write) -> Result<()> {
        self.validate()?;
        writer.write_all(&((self.payload.len() + 8) as u32).to_be_bytes())?;
        writer.write_all(&[VERSION, self.kind as u8, 0, 0])?;
        writer.write_all(&self.stream_id.to_be_bytes())?;
        writer.write_all(&self.payload)?;
        Ok(())
    }
    pub fn read(reader: &mut impl Read) -> Result<Self> {
        let mut prefix = [0; 4];
        reader.read_exact(&mut prefix)?;
        let length = u32::from_be_bytes(prefix) as usize;
        ensure!(
            (8..=MAX_FRAME).contains(&length),
            "프레임 길이가 허용 범위 밖입니다"
        );
        let mut header = [0; 8];
        reader.read_exact(&mut header)?;
        ensure!(
            header[0] == VERSION && header[2..4] == [0, 0],
            "지원하지 않는 버전 또는 flags입니다"
        );
        let kind = FrameType::try_from(header[1])?;
        let stream_id = u32::from_be_bytes(header[4..].try_into()?);
        let mut payload = vec![0; length - 8];
        reader.read_exact(&mut payload)?;
        let frame = Self {
            kind,
            stream_id,
            payload,
        };
        frame.validate()?;
        Ok(frame)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub max_frame: u32,
    pub connection_credit: u32,
    pub stream_credit: u32,
    pub capabilities: u32,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            max_frame: MAX_FRAME as u32,
            connection_credit: 4 * 1024 * 1024,
            stream_credit: 256 * 1024,
            capabilities: 7,
        }
    }
}
impl Settings {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = b"MTSPLIT1".to_vec();
        for value in [
            self.max_frame,
            self.connection_credit,
            self.stream_credit,
            self.capabilities,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        Self::decode(&bytes)?;
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == 24 && bytes[..8] == *b"MTSPLIT1",
            "HELLO/WELCOME 식별자가 잘못됐습니다"
        );
        let value = |offset| {
            u32::from_be_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .expect("검증한 설정 길이"),
            )
        };
        let settings = Self {
            max_frame: value(8),
            connection_credit: value(12),
            stream_credit: value(16),
            capabilities: value(20),
        };
        ensure!(
            (65515..=MAX_FRAME as u32).contains(&settings.max_frame),
            "협상 프레임 한도가 너무 작거나 큽니다"
        );
        ensure!(
            (1..=0x7fff_ffff).contains(&settings.connection_credit)
                && (1..=0x7fff_ffff).contains(&settings.stream_credit),
            "초기 윈도가 잘못됐습니다"
        );
        ensure!(
            settings.capabilities & !7 == 0,
            "알 수 없는 필수 기능 비트입니다"
        );
        if settings.capabilities & 2 != 0 {
            ensure!(
                settings.connection_credit >= MAX_DATAGRAM as u32
                    && settings.stream_credit >= MAX_DATAGRAM as u32,
                "UDP 지원에는 최대 데이터그램을 수용하는 초기 윈도가 필요합니다"
            );
        }
        Ok(settings)
    }
}
