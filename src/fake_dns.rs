//! 외부 DNS 조회 없이 A 응답을 합성하고 RFC 2544 주소를 도메인에 대응시킨다.
//! 살아 있는 DNS 임대는 LRU에서 축출하지 않으며 할당했던 주소는 재사용하지 않는다.

use crate::paths::AppPaths;
use anyhow::{Context, Result, bail};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::Ipv4Addr, num::NonZeroUsize};
use thiserror::Error;

pub const DNS_TTL: u32 = 60;
const BASE: u32 = u32::from_be_bytes([198, 18, 0, 0]);
const LAST: u32 = 131070;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DnsError {
    #[error("잘못되었거나 지원하지 않는 DNS 질의입니다")]
    Malformed,
    #[error("DNS 이름이 유효한 ASCII 도메인이 아닙니다")]
    Domain,
    #[error("모든 Fake-IP 항목이 사용 중이거나 DNS 임대가 남아 있습니다")]
    Capacity,
    #[error("재사용하지 않는 Fake-IP 주소 풀이 소진됐습니다")]
    Exhausted,
    #[error("Fake-IP 참조 수가 잘못됐습니다")]
    Reference,
}

pub fn is_fake(ip: Ipv4Addr) -> bool {
    u32::from(ip) & 0xfffe0000 == BASE
}

pub fn normalize_domain(domain: &str) -> std::result::Result<String, DnsError> {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    if domain.is_empty() || domain.len() > 253 || !domain.is_ascii() {
        return Err(DnsError::Domain);
    }
    if domain.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }) {
        return Err(DnsError::Domain);
    }
    Ok(domain.to_ascii_lowercase())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FakeEntry {
    pub domain: String,
    pub ip: Ipv4Addr,
    pub lease_until: u64,
    #[serde(skip)]
    pins: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheFile {
    version: u32,
    next_offset: u32,
    entries: Vec<FakeEntry>,
}

pub struct FakeIpCache {
    entries: LruCache<String, FakeEntry>,
    reverse: std::collections::HashMap<Ipv4Addr, String>,
    next_offset: u32,
}

impl FakeIpCache {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            entries: LruCache::new(capacity),
            reverse: std::collections::HashMap::new(),
            next_offset: 1,
        }
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn allocate(&mut self, domain: &str, now: u64) -> std::result::Result<Ipv4Addr, DnsError> {
        let domain = normalize_domain(domain)?;
        if let Some(entry) = self.entries.get_mut(&domain) {
            entry.lease_until = now.saturating_add(u64::from(DNS_TTL));
            return Ok(entry.ip);
        }
        if self.next_offset > LAST {
            return Err(DnsError::Exhausted);
        }
        if self.entries.len() == self.entries.cap().get() {
            let expired = self
                .entries
                .iter()
                .rev()
                .find(|(_, e)| e.pins == 0 && e.lease_until <= now)
                .map(|(key, _)| key.clone());
            let key = expired.ok_or(DnsError::Capacity)?;
            if let Some(entry) = self.entries.pop(&key) {
                self.reverse.remove(&entry.ip);
            }
        }
        let ip = Ipv4Addr::from(BASE + self.next_offset);
        self.next_offset += 1;
        self.entries.put(
            domain.clone(),
            FakeEntry {
                domain: domain.clone(),
                ip,
                lease_until: now.saturating_add(u64::from(DNS_TTL)),
                pins: 0,
            },
        );
        self.reverse.insert(ip, domain);
        Ok(ip)
    }

    pub fn domain(&mut self, ip: Ipv4Addr) -> Option<String> {
        let key = self.reverse.get(&ip)?.clone();
        self.entries.get(&key).map(|e| e.domain.clone())
    }

    pub fn pin(&mut self, ip: Ipv4Addr) -> std::result::Result<String, DnsError> {
        let key = self.reverse.get(&ip).ok_or(DnsError::Reference)?.clone();
        let entry = self.entries.get_mut(&key).ok_or(DnsError::Reference)?;
        entry.pins = entry.pins.checked_add(1).ok_or(DnsError::Reference)?;
        Ok(entry.domain.clone())
    }

    pub fn unpin(&mut self, ip: Ipv4Addr) -> std::result::Result<(), DnsError> {
        let key = self.reverse.get(&ip).ok_or(DnsError::Reference)?.clone();
        let entry = self.entries.get_mut(&key).ok_or(DnsError::Reference)?;
        entry.pins = entry.pins.checked_sub(1).ok_or(DnsError::Reference)?;
        Ok(())
    }

    pub fn persist(&self, paths: &AppPaths) -> Result<()> {
        let data = CacheFile {
            version: 1,
            next_offset: self.next_offset,
            entries: self
                .entries
                .iter()
                .rev()
                .map(|(_, entry)| entry.clone())
                .collect(),
        };
        paths.atomic_write(
            "runtime/fakeip_cache.json",
            &serde_json::to_vec_pretty(&data)?,
        )
    }

    pub fn load(paths: &AppPaths, capacity: NonZeroUsize) -> Result<Self> {
        let path = paths.resolve("runtime/fakeip_cache.json")?;
        let bytes = match std::fs::read(path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new(capacity)),
            Err(e) => return Err(e.into()),
        };
        if bytes.len() > 64 * 1024 * 1024 {
            bail!("Fake-IP 캐시 파일이 너무 큽니다");
        }
        let file: CacheFile = serde_json::from_slice(&bytes).context("Fake-IP 캐시 파싱 실패")?;
        if file.version != 1
            || !(1..=LAST + 1).contains(&file.next_offset)
            || file.entries.len() > capacity.get()
        {
            bail!("Fake-IP 캐시 버전 또는 용량이 잘못됐습니다");
        }
        let mut cache = Self::new(capacity);
        cache.next_offset = file.next_offset;
        for mut entry in file.entries {
            let normalized = normalize_domain(&entry.domain)?;
            if normalized != entry.domain || !is_fake(entry.ip) {
                bail!("잘못된 Fake-IP 캐시 항목입니다");
            }
            let offset = u32::from(entry.ip) - BASE;
            if offset == 0
                || offset >= cache.next_offset
                || cache.reverse.contains_key(&entry.ip)
                || cache.entries.contains(&entry.domain)
            {
                bail!("중복되거나 할당 범위를 벗어난 Fake-IP 항목입니다");
            }
            entry.pins = 0;
            cache.reverse.insert(entry.ip, entry.domain.clone());
            cache.entries.put(entry.domain.clone(), entry);
        }
        Ok(cache)
    }
}

fn read16(bytes: &[u8], offset: usize) -> std::result::Result<u16, DnsError> {
    let bytes = bytes.get(offset..offset + 2).ok_or(DnsError::Malformed)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// 압축 포인터의 순환과 확장 이름의 길이를 함께 제한한다.
pub fn decode_name(bytes: &[u8], start: usize) -> std::result::Result<(String, usize), DnsError> {
    let mut cursor = start;
    let mut consumed = None;
    let mut visited = HashSet::new();
    let mut labels = Vec::new();
    let mut expanded = 1usize;
    for _ in 0..128 {
        if !visited.insert(cursor) {
            return Err(DnsError::Malformed);
        }
        let length = *bytes.get(cursor).ok_or(DnsError::Malformed)?;
        if length & 0xc0 == 0xc0 {
            let low = *bytes.get(cursor + 1).ok_or(DnsError::Malformed)?;
            let pointer = ((usize::from(length) & 0x3f) << 8) | usize::from(low);
            // RFC 1035의 이전 이름 참조만 수락한다.
            if pointer >= cursor || pointer < 12 {
                return Err(DnsError::Malformed);
            }
            consumed.get_or_insert(cursor + 2);
            cursor = pointer;
        } else if length & 0xc0 != 0 {
            return Err(DnsError::Malformed);
        } else if length == 0 {
            return Ok((labels.join("."), consumed.unwrap_or(cursor + 1)));
        } else {
            let end = cursor + 1 + usize::from(length);
            let label = bytes.get(cursor + 1..end).ok_or(DnsError::Malformed)?;
            expanded += usize::from(length) + 1;
            if expanded > 255 {
                return Err(DnsError::Malformed);
            }
            labels.push(
                std::str::from_utf8(label)
                    .map_err(|_| DnsError::Domain)?
                    .to_owned(),
            );
            cursor = end;
        }
    }
    Err(DnsError::Malformed)
}

pub fn encode_name(domain: &str, output: &mut Vec<u8>) -> std::result::Result<(), DnsError> {
    let domain = normalize_domain(domain)?;
    for label in domain.split('.') {
        output.push(label.len() as u8);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    pub flags: u16,
    pub domain: String,
    pub original_name: String,
    pub qtype: u16,
    pub qclass: u16,
}

pub fn parse_question(bytes: &[u8]) -> std::result::Result<Question, DnsError> {
    if bytes.len() < 12 || bytes.len() > 65535 {
        return Err(DnsError::Malformed);
    }
    let flags = read16(bytes, 2)?;
    if flags & !0x0130 != 0
        || read16(bytes, 4)? != 1
        || read16(bytes, 6)? != 0
        || read16(bytes, 8)? != 0
    {
        return Err(DnsError::Malformed);
    }
    let (name, end) = decode_name(bytes, 12)?;
    let domain = normalize_domain(&name)?;
    let qtype = read16(bytes, end)?;
    let qclass = read16(bytes, end + 2)?;
    let mut cursor = end + 4;
    let additional = read16(bytes, 10)?;
    if additional > 1 {
        return Err(DnsError::Malformed);
    }
    if additional == 1 {
        // EDNS 옵션은 크기를 검증한 후 버린다. 응답에는 지원하지 않는 기능을 광고하지 않는다.
        let (name, end) = decode_name(bytes, cursor)?;
        if !name.is_empty() || read16(bytes, end)? != 41 {
            return Err(DnsError::Malformed);
        }
        let length = usize::from(read16(bytes, end + 8)?);
        cursor = end.checked_add(10 + length).ok_or(DnsError::Malformed)?;
        if cursor > bytes.len() {
            return Err(DnsError::Malformed);
        }
    }
    if cursor != bytes.len() {
        return Err(DnsError::Malformed);
    }
    Ok(Question {
        id: read16(bytes, 0)?,
        flags,
        domain,
        original_name: name,
        qtype,
        qclass,
    })
}

/// AAAA에는 IPv4를 잘못 넣지 않고 NODATA를 반환한다. 외부 조회는 수행하지 않는다.
pub fn synthesize(
    query: &[u8],
    cache: &mut FakeIpCache,
    now: u64,
) -> std::result::Result<Vec<u8>, DnsError> {
    let question = parse_question(query)?;
    let mut rcode = if question.qclass != 1 || !matches!(question.qtype, 1 | 28) {
        4
    } else {
        0
    };
    let answer = if rcode == 0 && question.qtype == 1 {
        match cache.allocate(&question.domain, now) {
            Ok(ip) => Some(ip),
            Err(DnsError::Capacity | DnsError::Exhausted) => {
                rcode = 2;
                None
            }
            Err(e) => return Err(e),
        }
    } else {
        None
    };
    response(&question, answer, rcode)
}

pub fn error_response(query: &[u8], rcode: u16) -> std::result::Result<Vec<u8>, DnsError> {
    if rcode > 15 {
        return Err(DnsError::Malformed);
    }
    response(&parse_question(query)?, None, rcode)
}

fn response(
    question: &Question,
    answer: Option<Ipv4Addr>,
    rcode: u16,
) -> std::result::Result<Vec<u8>, DnsError> {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(&question.id.to_be_bytes());
    // AD를 설정하지 않는다. DNSSEC 검증을 수행한 응답이 아니기 때문이다.
    bytes.extend_from_slice(&(0x8080 | (question.flags & 0x0110) | rcode).to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&u16::from(answer.is_some()).to_be_bytes());
    bytes.extend_from_slice(&[0; 4]);
    // 정규화한 캐시 키와 달리 질문의 철자는 보존해 0x20 대소문자 검사를 깨뜨리지 않는다.
    for label in question.original_name.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&question.qtype.to_be_bytes());
    bytes.extend_from_slice(&question.qclass.to_be_bytes());
    if let Some(ip) = answer {
        bytes.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        bytes.extend_from_slice(&DNS_TTL.to_be_bytes());
        bytes.extend_from_slice(&[0, 4]);
        bytes.extend_from_slice(&ip.octets());
    }
    Ok(bytes)
}

/// TCP DNS의 길이 접두사를 처리하며 여러 질의가 붙은 경우에도 경계를 보존한다.
pub fn read_tcp_query(reader: &mut impl std::io::Read) -> Result<Vec<u8>> {
    let mut header = [0u8; 2];
    reader.read_exact(&mut header)?;
    let length = usize::from(u16::from_be_bytes(header));
    if length < 12 {
        bail!("TCP DNS 메시지가 너무 짧습니다");
    }
    let mut query = vec![0; length];
    reader.read_exact(&mut query)?;
    Ok(query)
}

pub fn write_tcp_response(writer: &mut impl std::io::Write, response: &[u8]) -> Result<()> {
    let length = u16::try_from(response.len()).context("TCP DNS 응답이 너무 큽니다")?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(response)?;
    Ok(())
}
