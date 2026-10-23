//! Telegram의 전송 난독화와 Fake-TLS를 구현한다.
//! 이 계층은 MTProto 메시지 암호화나 데이터 무결성을 대신하지 않는다.

use crate::fake_dns::normalize_domain;
use aes::Aes256;
use anyhow::{Context, Result, bail, ensure};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    io::{Read, Write},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

type AesCtr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;
pub const MAX_TLS_RECORD: usize = 16384;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ProxySecret {
    key: [u8; 16],
    domain: String,
}

impl fmt::Debug for ProxySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxySecret")
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

impl ProxySecret {
    pub fn parse(encoded: &str) -> Result<Self> {
        ensure!(
            encoded.len() <= 540 && encoded.len().is_multiple_of(2),
            "비밀값 길이가 잘못됐습니다"
        );
        let mut bytes = hex::decode(encoded).context("비밀값이 hex 형식이 아닙니다")?;
        let result = (|| {
            ensure!(
                bytes.len() >= 18 && bytes[0] == 0xee,
                "ee 비밀값과 SNI 도메인이 필요합니다"
            );
            let domain =
                std::str::from_utf8(&bytes[17..]).context("SNI 도메인이 UTF-8이 아닙니다")?;
            let domain = normalize_domain(domain)?;
            ensure!(
                !domain.contains('_'),
                "SNI 호스트에는 밑줄을 사용할 수 없습니다"
            );
            let key = bytes[1..17]
                .try_into()
                .context("비밀키 길이가 잘못됐습니다")?;
            Ok(Self { key, domain })
        })();
        bytes.zeroize();
        result
    }
    pub fn domain(&self) -> &str {
        &self.domain
    }
    pub fn key(&self) -> &[u8; 16] {
        &self.key
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DirectionKeys {
    pub tx_key: [u8; 32],
    pub tx_iv: [u8; 16],
    pub rx_key: [u8; 32],
    pub rx_iv: [u8; 16],
}

pub fn derive_keys(init: &[u8; 64], secret: &ProxySecret) -> DirectionKeys {
    let mut reversed = *init;
    reversed.reverse();
    let hash = |part: &[u8]| -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(part);
        hasher.update(secret.key());
        hasher.finalize().into()
    };
    let keys = DirectionKeys {
        tx_key: hash(&init[8..40]),
        tx_iv: init[40..56].try_into().expect("고정 길이 슬라이스"),
        rx_key: hash(&reversed[8..40]),
        rx_iv: reversed[40..56].try_into().expect("고정 길이 슬라이스"),
    };
    reversed.zeroize();
    keys
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportTag {
    Abridged,
    Intermediate,
    PaddedIntermediate,
}
impl TransportTag {
    pub fn bytes(self) -> [u8; 4] {
        [match self {
            Self::Abridged => 0xef,
            Self::Intermediate => 0xee,
            Self::PaddedIntermediate => 0xdd,
        }; 4]
    }
}

pub fn good_nonce(bytes: &[u8; 64]) -> bool {
    bytes[0] != 0xef
        && bytes[4..8] != [0; 4]
        && ![
            b"HEAD".as_slice(),
            b"POST",
            b"GET ",
            b"OPTI",
            &[0xee; 4],
            &[0xdd; 4],
            &[0x16, 3, 1, 2],
        ]
        .contains(&&bytes[..4])
}

pub struct ObfuscatedStream {
    tx: AesCtr,
    rx: AesCtr,
}
impl ObfuscatedStream {
    pub fn client(
        secret: &ProxySecret,
        dc: i16,
        tag: TransportTag,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<([u8; 64], Self)> {
        let mut init = [0; 64];
        loop {
            rng.fill_bytes(&mut init);
            if good_nonce(&init) {
                break;
            }
        }
        Self::client_from_nonce(init, secret, dc, tag)
    }

    pub fn client_from_nonce(
        mut init: [u8; 64],
        secret: &ProxySecret,
        dc: i16,
        tag: TransportTag,
    ) -> Result<([u8; 64], Self)> {
        ensure!(good_nonce(&init), "예약된 난독화 초기값입니다");
        init[56..60].copy_from_slice(&tag.bytes());
        init[60..62].copy_from_slice(&dc.to_le_bytes());
        let keys = derive_keys(&init, secret);
        let mut stream = Self {
            tx: AesCtr::new((&keys.tx_key).into(), (&keys.tx_iv).into()),
            rx: AesCtr::new((&keys.rx_key).into(), (&keys.rx_iv).into()),
        };
        let mut encrypted = init;
        stream.encrypt(&mut encrypted);
        let mut wire = init;
        wire[56..].copy_from_slice(&encrypted[56..]);
        init.zeroize();
        encrypted.zeroize();
        Ok((wire, stream))
    }

    /// 참조 서버와 상호운용 테스트에서 사용하는 역방향 초기화이다.
    pub fn server(
        wire: &[u8; 64],
        secret: &ProxySecret,
        expected: TransportTag,
    ) -> Result<(i16, Self)> {
        ensure!(good_nonce(wire), "예약된 난독화 초기값입니다");
        let keys = derive_keys(wire, secret);
        let mut stream = Self {
            tx: AesCtr::new((&keys.rx_key).into(), (&keys.rx_iv).into()),
            rx: AesCtr::new((&keys.tx_key).into(), (&keys.tx_iv).into()),
        };
        let mut plain = *wire;
        stream.decrypt(&mut plain);
        let valid = plain[56..60].ct_eq(&expected.bytes()).unwrap_u8() == 1;
        let dc = i16::from_le_bytes([plain[60], plain[61]]);
        plain.zeroize();
        ensure!(valid, "난독화 초기값의 전송 표식이 잘못됐습니다");
        Ok((dc, stream))
    }
    pub fn encrypt(&mut self, bytes: &mut [u8]) {
        self.tx.apply_keystream(bytes);
    }
    pub fn decrypt(&mut self, bytes: &mut [u8]) {
        self.rx.apply_keystream(bytes);
    }
}

fn push16(output: &mut Vec<u8>, value: usize) -> Result<()> {
    output.extend_from_slice(&u16::try_from(value)?.to_be_bytes());
    Ok(())
}
fn extension(output: &mut Vec<u8>, kind: u16, data: &[u8]) -> Result<()> {
    output.extend_from_slice(&kind.to_be_bytes());
    push16(output, data.len())?;
    output.extend_from_slice(data);
    Ok(())
}

fn digest(secret: &ProxySecret, bytes: &[u8]) -> [u8; 32] {
    let mut hmac = HmacSha256::new_from_slice(secret.key()).expect("HMAC는 16바이트 키를 지원한다");
    hmac.update(bytes);
    hmac.finalize().into_bytes().into()
}

#[derive(Clone)]
pub struct ClientHello {
    pub wire: Vec<u8>,
    pub random: [u8; 32],
    pub session_id: [u8; 32],
}

impl ClientHello {
    pub fn generate(
        secret: &ProxySecret,
        timestamp: u32,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self> {
        let mut session_id = [0; 32];
        rng.fill_bytes(&mut session_id);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.push(32);
        body.extend_from_slice(&session_id);
        body.extend_from_slice(&[
            0, 10, 0x13, 1, 0x13, 2, 0x13, 3, 0xc0, 0x2f, 0xc0, 0x30, 1, 0,
        ]);
        let mut extensions = Vec::new();
        let name = secret.domain().as_bytes();
        let mut sni = Vec::new();
        push16(&mut sni, name.len() + 3)?;
        sni.push(0);
        push16(&mut sni, name.len())?;
        sni.extend_from_slice(name);
        extension(&mut extensions, 0, &sni)?;
        extension(&mut extensions, 10, &[0, 4, 0, 29, 0, 23])?;
        extension(&mut extensions, 11, &[1, 0])?;
        extension(&mut extensions, 13, &[0, 8, 8, 4, 4, 3, 8, 7, 8, 5])?;
        extension(
            &mut extensions,
            16,
            &[
                0, 12, 2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
            ],
        )?;
        extension(&mut extensions, 43, &[2, 3, 4])?;
        extension(&mut extensions, 45, &[1, 1])?;
        let mut scalar = [0; 32];
        rng.fill_bytes(&mut scalar);
        let public = x25519_dalek::x25519(scalar, x25519_dalek::X25519_BASEPOINT_BYTES);
        scalar.zeroize();
        let mut share = vec![0, 36, 0, 29, 0, 32];
        share.extend_from_slice(&public);
        extension(&mut extensions, 51, &share)?;
        // 517바이트의 완전한 레코드가 되도록 TLS padding 확장을 사용한다.
        let unpadded = 5 + 4 + body.len() + 2 + extensions.len();
        if unpadded + 4 <= 517 {
            extension(&mut extensions, 21, &vec![0; 517 - unpadded - 4])?;
        }
        push16(&mut body, extensions.len())?;
        body.extend_from_slice(&extensions);
        let mut wire = vec![0x16, 3, 1];
        push16(&mut wire, body.len() + 4)?;
        wire.push(1);
        let length = u32::try_from(body.len())?.to_be_bytes();
        wire.extend_from_slice(&length[1..]);
        wire.extend_from_slice(&body);
        let mut random = digest(secret, &wire);
        for (slot, time) in random[28..].iter_mut().zip(timestamp.to_le_bytes()) {
            *slot ^= time;
        }
        wire[11..43].copy_from_slice(&random);
        Ok(Self {
            wire,
            random,
            session_id,
        })
    }
}

/// 서버 타임스탬프를 만들어 검증하지 않는다. 공식 응답 HMAC는 새 클라이언트 random에 결합된다.
pub fn verify_server_hello(secret: &ProxySecret, hello: &ClientHello, wire: &[u8]) -> Result<()> {
    ensure!(
        wire.len() <= 65536 && wire.len() >= 5 + 38 + 6 + 5,
        "ServerHello 길이가 잘못됐습니다"
    );
    ensure!(
        wire[..3] == [0x16, 3, 3],
        "ServerHello 레코드 종류가 잘못됐습니다"
    );
    let first_length = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
    let first_end = 5 + first_length;
    ensure!(
        first_end + 11 <= wire.len() && first_length >= 38,
        "ServerHello가 잘렸습니다"
    );
    ensure!(
        wire[5] == 2
            && wire[6] == 0
            && usize::from(u16::from_be_bytes([wire[7], wire[8]])) + 4 == first_length,
        "ServerHello 핸드셰이크 길이가 잘못됐습니다"
    );
    ensure!(
        wire[9..11] == [3, 3] && wire[43] == 32 && first_end >= 82,
        "ServerHello 형식이 잘못됐습니다"
    );
    ensure!(
        wire[44..76].ct_eq(&hello.session_id).unwrap_u8() == 1,
        "ServerHello 세션이 다릅니다"
    );
    ensure!(
        matches!(&wire[76..78], [0x13, 1] | [0x13, 2] | [0x13, 3]) && wire[78] == 0,
        "ServerHello 암호군이 잘못됐습니다"
    );
    let extensions_len = usize::from(u16::from_be_bytes([wire[79], wire[80]]));
    ensure!(
        81 + extensions_len == first_end,
        "ServerHello 확장 길이가 잘못됐습니다"
    );
    ensure!(
        wire[first_end..first_end + 9] == [0x14, 3, 3, 0, 1, 1, 0x17, 3, 3],
        "ServerHello 후속 레코드가 잘못됐습니다"
    );
    let last_length = usize::from(u16::from_be_bytes([
        wire[first_end + 9],
        wire[first_end + 10],
    ]));
    ensure!(
        first_end + 11 + last_length == wire.len(),
        "ServerHello 마지막 레코드 길이가 잘못됐습니다"
    );
    let mut authenticated = Vec::with_capacity(32 + wire.len());
    authenticated.extend_from_slice(&hello.random);
    authenticated.extend_from_slice(wire);
    let received = authenticated[43..75].to_vec();
    authenticated[43..75].fill(0);
    let mut hmac = HmacSha256::new_from_slice(secret.key()).expect("고정 HMAC 키 길이");
    hmac.update(&authenticated);
    hmac.verify_slice(&received)
        .context("ServerHello HMAC가 일치하지 않습니다")?;
    Ok(())
}

pub fn read_server_hello(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    for expected in [0x16, 0x14, 0x17] {
        let mut header = [0; 5];
        reader.read_exact(&mut header)?;
        ensure!(
            header[..3] == [expected, 3, 3],
            "ServerHello 레코드 순서가 잘못됐습니다"
        );
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        ensure!(
            output.len() + length + 5 <= 65536,
            "ServerHello 크기 한도 초과"
        );
        output.extend_from_slice(&header);
        let start = output.len();
        output.resize(start + length, 0);
        reader.read_exact(&mut output[start..])?;
    }
    Ok(output)
}

pub fn write_tls_records(writer: &mut impl Write, data: &[u8]) -> Result<()> {
    for chunk in data.chunks(MAX_TLS_RECORD) {
        writer.write_all(&[0x17, 3, 3])?;
        writer.write_all(&(chunk.len() as u16).to_be_bytes())?;
        writer.write_all(chunk)?;
    }
    Ok(())
}

pub fn read_tls_record(reader: &mut impl Read) -> Result<Vec<u8>> {
    // 빈 레코드 무한열도 하나의 read 호출을 영원히 붙잡지 못하도록 제한한다.
    for _ in 0..16 {
        let mut header = [0; 5];
        reader.read_exact(&mut header)?;
        ensure!(
            header[..3] == [0x17, 3, 3],
            "Application Data 레코드가 아닙니다"
        );
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        ensure!(
            length <= MAX_TLS_RECORD,
            "Application Data 레코드가 너무 큽니다"
        );
        let mut body = vec![0; length];
        reader.read_exact(&mut body)?;
        if !body.is_empty() {
            return Ok(body);
        }
    }
    bail!("빈 TLS 레코드가 너무 많습니다")
}

/// 확장 게이트웨이의 내부 TLS 바이트를 정확한 길이와 함께 패딩한다.
pub fn encode_extended_chunk(
    content: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>> {
    ensure!(
        !content.is_empty() && content.len() <= 16384,
        "확장 청크 길이가 잘못됐습니다"
    );
    use rand::Rng;
    let padding = rng.gen_range(4..=15);
    let length = 4 + content.len() + padding;
    let mut bytes = Vec::with_capacity(length + 4);
    bytes.extend_from_slice(&(length as u32).to_le_bytes());
    bytes.extend_from_slice(&(content.len() as u32).to_be_bytes());
    bytes.extend_from_slice(content);
    let start = bytes.len();
    bytes.resize(start + padding, 0);
    rng.fill_bytes(&mut bytes[start..]);
    Ok(bytes)
}

pub fn decode_extended_chunk(bytes: &[u8]) -> Result<&[u8]> {
    ensure!(
        bytes.len() >= 13 && bytes.len() <= 16407,
        "확장 청크 크기가 잘못됐습니다"
    );
    let total = u32::from_le_bytes(bytes[..4].try_into()?) as usize;
    let content = u32::from_be_bytes(bytes[4..8].try_into()?) as usize;
    ensure!(
        total + 4 == bytes.len() && (1..=16384).contains(&content),
        "확장 청크 길이가 잘못됐습니다"
    );
    let padding = bytes
        .len()
        .checked_sub(8 + content)
        .context("확장 청크 본문이 잘렸습니다")?;
    ensure!(
        (4..=15).contains(&padding),
        "확장 청크 패딩 길이가 잘못됐습니다"
    );
    Ok(&bytes[8..8 + content])
}

pub fn encode_standard_padded(
    payload: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>> {
    use rand::Rng;
    ensure!(
        !payload.is_empty() && payload.len() <= 1024 * 1024,
        "MTProto 프레임 크기가 잘못됐습니다"
    );
    let padding = rng.gen_range(4..=15);
    let mut bytes = Vec::with_capacity(4 + payload.len() + padding);
    bytes.extend_from_slice(&((payload.len() + padding) as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    let start = bytes.len();
    bytes.resize(start + padding, 0);
    rng.fill_bytes(&mut bytes[start..]);
    Ok(bytes)
}
