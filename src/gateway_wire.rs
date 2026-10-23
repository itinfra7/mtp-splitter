//! 게이트웨이 전송 규격을 내부 스트림 모델로 변환한다.
//! 비공개 구성의 mtp_tcp_v1은 기존 실험 규격과 명시적으로 구분한다.

use crate::protocol::{
    ErrorCode, ErrorMessage, Frame, FrameType, MAX_DATAGRAM, MAX_FRAME, Settings, Target,
    TargetAddress,
};
use anyhow::{Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WireDialect {
    #[default]
    Legacy,
    GatewayV1,
}

impl WireDialect {
    pub fn alpn(self) -> &'static [u8] {
        match self {
            Self::Legacy => b"mtp-splitter/1",
            Self::GatewayV1 => b"mtp-gateway/1",
        }
    }
    pub fn local_settings(self) -> Settings {
        match self {
            Self::Legacy => Settings::default(),
            Self::GatewayV1 => Settings {
                connection_credit: 524288,
                stream_credit: 131072,
                ..Settings::default()
            },
        }
    }
    pub fn credit(self, payload: usize) -> usize {
        payload + if self == Self::GatewayV1 { 64 } else { 0 }
    }
    pub fn hello(self, settings: &Settings) -> Result<Vec<u8>> {
        if self == Self::Legacy {
            return settings.encode();
        }
        validate_windows(settings)?;
        let mut bytes = Vec::with_capacity(12);
        for value in [
            settings.connection_credit,
            settings.stream_credit,
            settings.capabilities,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        Ok(bytes)
    }
    pub fn welcome(self, bytes: &[u8]) -> Result<Negotiation> {
        if self == Self::Legacy {
            return Ok(Negotiation {
                settings: Settings::decode(bytes)?,
                tcp_limit: usize::MAX,
                udp_limit: usize::MAX,
                udp_idle_seconds: 120,
            });
        }
        ensure!(bytes.len() == 20, "WELCOME 본문은 20바이트여야 합니다");
        let value =
            |offset| u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("검증한 길이"));
        let settings = Settings {
            connection_credit: value(0),
            stream_credit: value(4),
            capabilities: value(8),
            ..Settings::default()
        };
        validate_windows(&settings)?;
        let tcp_limit = usize::from(u16::from_be_bytes(bytes[12..14].try_into()?));
        let udp_limit = usize::from(u16::from_be_bytes(bytes[14..16].try_into()?));
        let udp_idle_seconds = value(16);
        ensure!(
            tcp_limit > 0 && udp_limit > 0 && udp_idle_seconds > 0,
            "WELCOME 자원 한도가 잘못됐습니다"
        );
        Ok(Negotiation {
            settings,
            tcp_limit,
            udp_limit,
            udp_idle_seconds,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Negotiation {
    pub settings: Settings,
    pub tcp_limit: usize,
    pub udp_limit: usize,
    pub udp_idle_seconds: u32,
}

fn validate_windows(settings: &Settings) -> Result<()> {
    ensure!(
        (131072..=4194304).contains(&settings.connection_credit)
            && (131072..=1048576).contains(&settings.stream_credit)
            && settings.capabilities == 7,
        "게이트웨이 수신 윈도 또는 기능 비트가 잘못됐습니다"
    );
    Ok(())
}

/// 서버 오류를 내부 오류 분류에 대응시킨다. 미정의 코드는 연결 오류로 처리한다.
fn server_error(code: u16, message: &str) -> Result<Vec<u8>> {
    let (mapped, fallback) = match code {
        1 => (ErrorCode::Policy, "목적지 접근 거부"),
        2 | 3 => (ErrorCode::Host, "사용 가능한 도메인 주소 없음"),
        4 => (ErrorCode::Network, "원격 DNS 서버 실패"),
        5 | 7 | 11 => (ErrorCode::Timeout, "원격 처리 또는 유휴 시간 초과"),
        6 => (ErrorCode::Refused, "목적지 연결 거부"),
        8 => (ErrorCode::Capacity, "서버 자원 한도 초과"),
        9 => (ErrorCode::Unsupported, "지원하지 않는 기능"),
        10 | 14 | 16 => (ErrorCode::Protocol, "원격 프로토콜 오류"),
        12 => (ErrorCode::Network, "원격 소켓 통신 실패"),
        13 | 18 => (ErrorCode::Policy, "인증 또는 권한 거부"),
        15 => (ErrorCode::Cancelled, "서버 종료"),
        17 => (ErrorCode::Capacity, "원격 메시지 크기 초과"),
        _ => bail!("정의되지 않은 서버 오류 코드입니다"),
    };
    ErrorMessage::new(
        mapped,
        if message.is_empty() {
            fallback
        } else {
            message
        },
    )
    .encode()
}

fn client_error(payload: &[u8]) -> Result<u16> {
    Ok(match ErrorMessage::decode(payload)?.code {
        ErrorCode::Cancelled => 10,
        ErrorCode::General | ErrorCode::Network => 12,
        ErrorCode::Policy => 1,
        ErrorCode::Host => 2,
        ErrorCode::Refused => 6,
        ErrorCode::Timeout => 7,
        ErrorCode::Unsupported => 9,
        ErrorCode::Address | ErrorCode::Protocol => 14,
        ErrorCode::Capacity => 8,
    })
}

pub async fn write_client(
    writer: &mut (impl AsyncWrite + Unpin),
    dialect: WireDialect,
    frame: &Frame,
) -> Result<()> {
    if dialect == WireDialect::Legacy {
        return crate::transport::write_frame(writer, frame).await;
    }
    frame.validate()?;
    let kind = match frame.kind {
        FrameType::WindowUpdate => 0x24,
        FrameType::Ping => 0x30,
        FrameType::Pong => 0x31,
        FrameType::GoAway => 0x32,
        other => other as u8,
    };
    let mut id = frame.stream_id;
    let payload = match frame.kind {
        FrameType::Hello => dialect.hello(&Settings::decode(&frame.payload)?)?,
        FrameType::DnsQuery => {
            id = 0;
            let mut bytes = frame.stream_id.to_be_bytes().to_vec();
            bytes.extend_from_slice(&frame.payload);
            bytes
        }
        FrameType::StreamReset => client_error(&frame.payload)?.to_be_bytes().to_vec(),
        FrameType::GoAway => {
            let mut bytes = client_error(&frame.payload)?.to_be_bytes().to_vec();
            bytes.extend_from_slice(&0u32.to_be_bytes());
            bytes
        }
        FrameType::Welcome | FrameType::OpenOk | FrameType::OpenError | FrameType::DnsResponse => {
            bail!("클라이언트가 서버 전용 프레임을 보낼 수 없습니다")
        }
        _ => frame.payload.clone(),
    };
    writer
        .write_all(&((payload.len() + 8) as u32).to_be_bytes())
        .await?;
    writer.write_all(&[1, kind, 0, 0]).await?;
    writer.write_all(&id.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_server(
    reader: &mut (impl AsyncRead + Unpin),
    dialect: WireDialect,
) -> Result<Frame> {
    if dialect == WireDialect::Legacy {
        return crate::transport::read_frame(reader).await;
    }
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix).await?;
    let length = u32::from_be_bytes(prefix) as usize;
    ensure!(
        (8..=MAX_FRAME).contains(&length),
        "게이트웨이 프레임 길이 오류"
    );
    let mut header = [0; 8];
    reader.read_exact(&mut header).await?;
    ensure!(
        header[0] == 1 && header[2..4] == [0, 0],
        "게이트웨이 버전 또는 flags 오류"
    );
    let mut id = u32::from_be_bytes(header[4..8].try_into()?);
    let mut payload = vec![0; length - 8];
    reader.read_exact(&mut payload).await?;
    let mut kind = match header[1] {
        0x24 => FrameType::WindowUpdate,
        0x30 => FrameType::Ping,
        0x31 => FrameType::Pong,
        0x32 => FrameType::GoAway,
        0x33 => bail!("정의되지 않은 게이트웨이 프레임입니다"),
        other => FrameType::try_from(other)?,
    };
    match kind {
        FrameType::Welcome => {
            ensure!(id == 0, "WELCOME 스트림 ID 오류");
            // 원래 WELCOME의 자원 한도는 연결 협상 단계에서 따로 읽는다.
            dialect.welcome(&payload)?;
            return Ok(Frame {
                kind,
                stream_id: id,
                payload,
            });
        }
        FrameType::OpenError => {
            ensure!((2..=194).contains(&payload.len()), "OPEN_ERROR 길이 오류");
            payload = server_error(
                u16::from_be_bytes(payload[..2].try_into()?),
                std::str::from_utf8(&payload[2..])?,
            )?;
        }
        FrameType::StreamReset => {
            ensure!(payload.len() == 2, "RESET 길이 오류");
            payload = server_error(u16::from_be_bytes(payload[..2].try_into()?), "")?;
        }
        FrameType::GoAway => {
            ensure!(id == 0 && payload.len() == 6, "GOAWAY 길이 또는 ID 오류");
            let last = u32::from_be_bytes(payload[2..6].try_into()?);
            ensure!(last == 0 || last & 1 == 1, "GOAWAY 마지막 ID 오류");
            payload = server_error(u16::from_be_bytes(payload[..2].try_into()?), "")?;
        }
        FrameType::DnsResponse => {
            ensure!(
                id == 0 && (6..=65541).contains(&payload.len()),
                "DNS 응답 길이 또는 ID 오류"
            );
            id = u32::from_be_bytes(payload[..4].try_into()?);
            let status = u16::from_be_bytes(payload[4..6].try_into()?);
            if status == 0 {
                payload.drain(..6);
            } else {
                ensure!(payload.len() <= 198, "DNS 오류 설명이 너무 깁니다");
                payload = server_error(status, std::str::from_utf8(&payload[6..])?)?;
                kind = FrameType::StreamReset;
            }
        }
        FrameType::UdpDatagram => {
            let (source, offset) = Target::decode(&payload)?;
            ensure!(
                matches!(source.address, TargetAddress::Ip(_))
                    && payload.len() - offset <= MAX_DATAGRAM,
                "UDP 응답의 출발지 또는 크기 오류"
            );
            ensure!(id != 0 && id & 1 == 1, "UDP 스트림 ID 오류");
            // 출발지와 흐름 크레딧 검증이 끝날 때까지 주소 헤더를 보존한다.
            return Ok(Frame {
                kind,
                stream_id: id,
                payload,
            });
        }
        FrameType::Hello | FrameType::OpenTcp | FrameType::OpenUdp | FrameType::DnsQuery => {
            bail!("서버가 클라이언트 전용 프레임을 보냈습니다")
        }
        _ => (),
    }
    let frame = Frame {
        kind,
        stream_id: id,
        payload,
    };
    frame.validate()?;
    Ok(frame)
}
