//! 실제 파일과 독립 Python/OpenSSL 벡터로 DNS·암호화·NAT 경계 조건을 검증한다.

use mtp_splitter::{
    config::{ProcessRule, ServerConfig},
    fake_dns::{self, DnsError, FakeIpCache},
    mtproto_core::{self, ClientHello, ObfuscatedStream, ProxySecret, TransportTag},
    nat_engine::{self, FlowKey, KillSwitchAction, NatSessionTable, TunnelState, TunnelStatus},
    packet::{self, PacketError, Protocol},
    paths::AppPaths,
    process_tracker::{
        ActiveSocketTable, Ownership, ProcessIdentity, ProcessTracker, SocketKey, SocketOwner,
    },
    protocol::{Frame, FrameType, Settings, Target, TargetAddress},
    shared_state::SharedState,
    watchdog::{GuardState, WatchdogPolicy},
};
use rand::{SeedableRng, rngs::StdRng};
use std::{
    io::{Cursor, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

fn secret() -> ProxySecret {
    ProxySecret::parse("ee000102030405060708090a0b0c0d0e0f6578616d706c652e636f6d").unwrap()
}
fn cache(size: usize) -> FakeIpCache {
    FakeIpCache::new(NonZeroUsize::new(size).unwrap())
}
fn address(value: &str) -> SocketAddr {
    value.parse().unwrap()
}
fn query(name: &str, kind: u16) -> Vec<u8> {
    let mut bytes = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    fake_dns::encode_name(name, &mut bytes).unwrap();
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&[0, 1]);
    bytes
}
fn fixture(name: &str) -> Vec<u8> {
    let packets: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/packets.json")).unwrap();
    hex::decode(packets[name].as_str().unwrap()).unwrap()
}
fn process(pid: u32, parent: u32, time: u64, image: &str) -> ProcessIdentity {
    ProcessIdentity {
        pid,
        parent,
        creation_time: time,
        image: PathBuf::from(image),
    }
}
fn rule(children: bool) -> ProcessRule {
    ProcessRule {
        exe_name: Some("launcher.exe".into()),
        path_glob: None,
        sha256: None,
        include_children: children,
    }
}

struct Directory {
    root: PathBuf,
    paths: AppPaths,
}
impl Directory {
    fn new() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("runtime/tmp")
            .join(format!(
                "test-{}-{:016x}",
                std::process::id(),
                rand::random::<u64>()
            ));
        std::fs::create_dir_all(&root).unwrap();
        let paths = AppPaths::new(root.clone()).unwrap();
        paths.prepare().unwrap();
        Self { root, paths }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .unwrap();
        if let Ok(root) = self.root.canonicalize() {
            assert!(root.starts_with(workspace.join("runtime/tmp")));
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}

#[test]
fn fake_ip_unique_normalized_and_bidirectional() {
    let mut cache = cache(4);
    let first = cache.allocate("EXAMPLE.com.", 0).unwrap();
    assert_eq!(first, cache.allocate("example.com", 1).unwrap());
    assert!(fake_dns::is_fake(first));
    assert_eq!(cache.domain(first).as_deref(), Some("example.com"));
    assert_ne!(first, cache.allocate("different.example", 1).unwrap());
}

#[test]
fn fake_ip_lru_evicts_only_expired_and_never_reuses_address() {
    let mut cache = cache(2);
    let a = cache.allocate("a.example", 0).unwrap();
    let b = cache.allocate("b.example", 0).unwrap();
    assert_eq!(cache.allocate("c.example", 59), Err(DnsError::Capacity));
    cache.allocate("a.example", 61).unwrap();
    let c = cache.allocate("c.example", 61).unwrap();
    assert_eq!(cache.domain(a).as_deref(), Some("a.example"));
    assert!(cache.domain(b).is_none());
    assert_ne!(b, c);
}

#[test]
fn fake_ip_pinned_entry_survives_expired_lease() {
    let mut cache = cache(1);
    let ip = cache.allocate("a.example", 0).unwrap();
    cache.pin(ip).unwrap();
    assert_eq!(cache.allocate("b.example", 120), Err(DnsError::Capacity));
    cache.unpin(ip).unwrap();
    assert!(cache.unpin(ip).is_err());
    assert!(cache.allocate("b.example", 120).is_ok());
}

#[test]
fn fake_ip_persistence_keeps_address_high_watermark() {
    let dir = Directory::new();
    let mut original = cache(1);
    let a = original.allocate("a.example", 0).unwrap();
    let b = original.allocate("b.example", 61).unwrap();
    original.persist(&dir.paths).unwrap();
    let mut loaded = FakeIpCache::load(&dir.paths, NonZeroUsize::new(1).unwrap()).unwrap();
    assert_eq!(loaded.domain(b).as_deref(), Some("b.example"));
    assert!(loaded.domain(a).is_none());
    assert_ne!(loaded.allocate("c.example", 122).unwrap(), a);
}

#[test]
fn fake_ip_corrupt_snapshot_is_rejected() {
    let dir = Directory::new();
    std::fs::write(dir.paths.resolve("runtime/fakeip_cache.json").unwrap(), br#"{"version":1,"next_offset":1,"entries":[{"domain":"a.example","ip":"198.18.0.1","lease_until":1}]}"#).unwrap();
    assert!(FakeIpCache::load(&dir.paths, NonZeroUsize::new(10).unwrap()).is_err());
}

#[test]
fn dns_a_response_has_correct_question_pointer_ttl_and_rdata() {
    let mut cache = cache(8);
    let response = fake_dns::synthesize(&query("example.com", 1), &mut cache, 0).unwrap();
    assert_eq!(
        &response[..12],
        &[0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]
    );
    let (_, question_end) = fake_dns::decode_name(&response, 12).unwrap();
    let rr = question_end + 4;
    assert_eq!(
        &response[rr..rr + 12],
        &[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]
    );
    assert_eq!(&response[rr + 12..], &[198, 18, 0, 1]);
    assert_eq!(
        fake_dns::decode_name(&response, rr).unwrap().0,
        "example.com"
    );
}

#[test]
fn dns_aaaa_is_nodata_without_invalid_ipv4_answer() {
    let mut cache = cache(1);
    let response = fake_dns::synthesize(&query("example.com", 28), &mut cache, 0).unwrap();
    assert_eq!(&response[6..8], &[0, 0]);
    assert_eq!(response[3] & 15, 0);
    assert!(cache.is_empty());
}

#[test]
fn dns_capacity_is_servfail_without_upstream_fallback() {
    let mut cache = cache(1);
    cache.allocate("busy.example", 0).unwrap();
    let response = fake_dns::synthesize(&query("another.example", 1), &mut cache, 1).unwrap();
    assert_eq!(response[3] & 15, 2);
}

#[test]
fn dns_unknown_type_is_not_advertised_as_success() {
    let response = fake_dns::synthesize(&query("example.com", 65), &mut cache(1), 0).unwrap();
    assert_eq!(response[3] & 15, 4);
}

#[test]
fn dns_edns_is_length_checked_and_ad_flag_is_not_copied() {
    let mut request = query("example.com", 1);
    request[3] = 0x20;
    request[11] = 1;
    request.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
    let response = fake_dns::synthesize(&request, &mut cache(1), 0).unwrap();
    assert_eq!(response[3] & 0x20, 0);
    assert_eq!(&response[10..12], &[0, 0]);
    request.pop();
    assert!(fake_dns::parse_question(&request).is_err());
}

#[test]
fn dns_rejects_cycles_truncation_multiple_questions_and_trailing_garbage() {
    let cycle = [vec![0; 12], vec![0xc0, 12]].concat();
    assert!(fake_dns::decode_name(&cycle, 12).is_err());
    let valid = query("example.com", 1);
    for length in 0..valid.len() {
        assert!(fake_dns::parse_question(&valid[..length]).is_err());
    }
    let mut invalid = valid.clone();
    invalid[5] = 2;
    assert!(fake_dns::parse_question(&invalid).is_err());
    let mut invalid = valid;
    invalid.push(0);
    assert!(fake_dns::parse_question(&invalid).is_err());
}

#[test]
fn dns_tcp_preserves_multiple_message_boundaries() {
    let first = query("a.example", 1);
    let second = query("b.example", 28);
    let mut bytes = Vec::new();
    fake_dns::write_tcp_response(&mut bytes, &first).unwrap();
    fake_dns::write_tcp_response(&mut bytes, &second).unwrap();
    let mut reader = Cursor::new(bytes);
    assert_eq!(fake_dns::read_tcp_query(&mut reader).unwrap(), first);
    assert_eq!(fake_dns::read_tcp_query(&mut reader).unwrap(), second);
}

#[test]
fn invalid_domains_are_rejected_without_allocation() {
    for domain in ["", "a..b", "a/b", "a\0b", "한글.example"] {
        assert!(cache(1).allocate(domain, 0).is_err());
    }
    assert!(fake_dns::normalize_domain(&format!("{}.com", "a".repeat(64))).is_err());
}

#[test]
fn ee_secret_requires_prefix_key_domain_and_redacts_key() {
    for value in [
        "",
        "ee",
        "dd000102030405060708090a0b0c0d0e0f6578616d706c652e636f6d",
        "ee000102030405060708090a0b0c0d0e0f",
        "zz",
    ] {
        assert!(ProxySecret::parse(value).is_err());
    }
    assert_eq!(secret().domain(), "example.com");
    assert!(!format!("{:?}", secret()).contains("000102"));
}

#[test]
fn obfuscated_keys_wire_and_continuation_match_python_openssl() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/obfuscated.json")).unwrap();
    let nonce = std::array::from_fn(|index| index as u8);
    let keys = mtproto_core::derive_keys(&nonce, &secret());
    for (name, actual) in [
        ("tx_key", keys.tx_key.as_slice()),
        ("rx_key", keys.rx_key.as_slice()),
        ("tx_iv", keys.tx_iv.as_slice()),
        ("rx_iv", keys.rx_iv.as_slice()),
    ] {
        assert_eq!(hex::encode(actual), vector[name].as_str().unwrap());
    }
    let (wire, mut stream) =
        ObfuscatedStream::client_from_nonce(nonce, &secret(), 2, TransportTag::PaddedIntermediate)
            .unwrap();
    assert_eq!(hex::encode(wire), vector["wire"].as_str().unwrap());
    let mut payload = hex::decode(vector["payload"].as_str().unwrap()).unwrap();
    stream.encrypt(&mut payload[..13]);
    stream.encrypt(&mut payload[13..]);
    assert_eq!(hex::encode(payload), vector["ciphertext"].as_str().unwrap());
}

#[test]
fn obfuscated_bidirectional_stream_survives_arbitrary_chunking() {
    let mut rng = StdRng::seed_from_u64(7);
    let (wire, mut client) =
        ObfuscatedStream::client(&secret(), -2, TransportTag::PaddedIntermediate, &mut rng)
            .unwrap();
    let (dc, mut server) =
        ObfuscatedStream::server(&wire, &secret(), TransportTag::PaddedIntermediate).unwrap();
    assert_eq!(dc, -2);
    for size in [1, 15, 16, 17, 63, 64, 8192] {
        let plain = vec![size as u8; size];
        let mut wire = plain.clone();
        client.encrypt(&mut wire);
        for part in wire.chunks_mut(7) {
            server.decrypt(part);
        }
        assert_eq!(wire, plain);
        server.encrypt(&mut wire);
        for part in wire.chunks_mut(13) {
            client.decrypt(part);
        }
        assert_eq!(wire, plain);
    }
}

#[test]
fn obfuscated_rejects_wrong_secret_and_reserved_nonce() {
    let mut nonce = [1; 64];
    nonce[..4].copy_from_slice(b"POST");
    assert!(
        ObfuscatedStream::client_from_nonce(nonce, &secret(), 2, TransportTag::PaddedIntermediate)
            .is_err()
    );
    let (wire, _) = ObfuscatedStream::client(
        &secret(),
        2,
        TransportTag::PaddedIntermediate,
        &mut StdRng::seed_from_u64(5),
    )
    .unwrap();
    let other =
        ProxySecret::parse("ee100102030405060708090a0b0c0d0e0f6578616d706c652e636f6d").unwrap();
    assert!(ObfuscatedStream::server(&wire, &other, TransportTag::PaddedIntermediate).is_err());
}

#[test]
fn fake_tls_client_hello_has_consistent_lengths_sni_and_timestamp_hmac() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let hello =
        ClientHello::generate(&secret(), 1700000000, &mut StdRng::seed_from_u64(9)).unwrap();
    assert_eq!(hello.wire.len(), 517);
    assert_eq!(
        usize::from(u16::from_be_bytes([hello.wire[3], hello.wire[4]])) + 5,
        hello.wire.len()
    );
    assert!(hello.wire.windows(11).any(|v| v == b"example.com"));
    let mut normalized = hello.wire.clone();
    normalized[11..43].fill(0);
    let mut hmac = Hmac::<Sha256>::new_from_slice(secret().key()).unwrap();
    hmac.update(&normalized);
    let digest = hmac.finalize().into_bytes();
    assert_eq!(&hello.random[..28], &digest[..28]);
    let mut recovered = [0; 4];
    for index in 0..4 {
        recovered[index] = digest[28 + index] ^ hello.random[28 + index];
    }
    assert_eq!(u32::from_le_bytes(recovered), 1700000000);
}

fn tls_fixture() -> (ClientHello, Vec<u8>) {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/fake_tls.json")).unwrap();
    let hello = ClientHello {
        wire: hex::decode(fixture["client"].as_str().unwrap()).unwrap(),
        random: hex::decode(fixture["random"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        session_id: hex::decode(fixture["session_id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    (
        hello,
        hex::decode(fixture["server"].as_str().unwrap()).unwrap(),
    )
}

#[test]
fn fake_tls_server_auth_matches_independent_python_vector() {
    let (hello, wire) = tls_fixture();
    mtproto_core::verify_server_hello(&secret(), &hello, &wire).unwrap();
    let read = mtproto_core::read_server_hello(&mut Cursor::new(&wire)).unwrap();
    assert_eq!(read, wire);
}

#[test]
fn fake_tls_rejects_mutations_truncation_and_replay_with_different_client() {
    let (hello, wire) = tls_fixture();
    for position in 0..wire.len() {
        let mut damaged = wire.clone();
        damaged[position] ^= 1;
        assert!(
            mtproto_core::verify_server_hello(&secret(), &hello, &damaged).is_err(),
            "위치 {position}"
        );
        assert!(
            mtp_splitter::mtproto_core::verify_server_hello(&secret(), &hello, &wire[..position])
                .is_err()
        );
    }
    let different =
        ClientHello::generate(&secret(), 1700000000, &mut StdRng::seed_from_u64(22)).unwrap();
    assert!(mtproto_core::verify_server_hello(&secret(), &different, &wire).is_err());
}

#[test]
fn tls_records_split_large_payload_without_losing_boundaries() {
    let payload: Vec<_> = (0..40001).map(|v| v as u8).collect();
    let mut bytes = Vec::new();
    mtproto_core::write_tls_records(&mut bytes, &payload).unwrap();
    let mut cursor = Cursor::new(bytes);
    let mut restored = Vec::new();
    for _ in 0..3 {
        restored.extend(mtp_splitter::mtproto_core::read_tls_record(&mut cursor).unwrap());
    }
    assert_eq!(restored, payload);
}

#[test]
fn extended_chunk_roundtrip_handles_padding_and_rejects_invalid_lengths() {
    let mut rng = StdRng::seed_from_u64(1);
    for size in [1, 15, 16, 200, 16384] {
        let payload = vec![42; size];
        let bytes = mtproto_core::encode_extended_chunk(&payload, &mut rng).unwrap();
        assert_eq!(
            mtproto_core::decode_extended_chunk(&bytes).unwrap(),
            payload
        );
        assert!((4..=15).contains(&(bytes.len() - 8 - size)));
        for length in 0..bytes.len() {
            assert!(mtproto_core::decode_extended_chunk(&bytes[..length]).is_err());
        }
    }
    assert!(mtproto_core::encode_extended_chunk(&[], &mut rng).is_err());
    let mut invalid = mtproto_core::encode_extended_chunk(b"abc", &mut rng).unwrap();
    invalid[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(mtproto_core::decode_extended_chunk(&invalid).is_err());
}

#[test]
fn packet_checksums_match_independent_python_vectors() {
    assert_eq!(
        packet::checksum(&hex::decode("0001f203f4f5f6f7").unwrap()),
        0x220d
    );
    for name in ["ipv4_udp", "ipv6_udp", "ipv4_tcp", "ipv6_tcp"] {
        let bytes = fixture(name);
        assert!(packet::checksums_valid(&bytes).unwrap(), "{name}");
        let mut recalculated = bytes.clone();
        packet::recalculate(&mut recalculated).unwrap();
        assert_eq!(recalculated, bytes);
    }
}

#[test]
fn packet_header_mutations_preserve_payload_and_checksums() {
    for name in ["ipv4_udp", "ipv6_udp", "ipv4_tcp", "ipv6_tcp"] {
        let mut bytes = fixture(name);
        let meta = packet::parse(&bytes).unwrap();
        let payload = bytes[meta.payload..].to_vec();
        let (source, target) = if meta.ipv6 {
            (address("[::1]:30000"), address("[::1]:13080"))
        } else {
            (address("127.0.0.2:30000"), address("127.0.0.1:13080"))
        };
        packet::rewrite(&mut bytes, source, target).unwrap();
        let modified = packet::parse(&bytes).unwrap();
        assert_eq!(modified.source, source);
        assert_eq!(modified.destination, target);
        assert_eq!(&bytes[modified.payload..], payload);
        assert!(packet::checksums_valid(&bytes).unwrap());
    }
}

#[test]
fn packet_rejects_truncation_fragments_and_wrong_address_family() {
    let original = fixture("ipv4_udp");
    for size in 0..original.len() {
        assert!(packet::parse(&original[..size]).is_err());
    }
    let mut fragment = original.clone();
    fragment[6] |= 0x20;
    assert_eq!(packet::parse(&fragment), Err(PacketError::Fragment));
    let mut bytes = original;
    assert!(packet::rewrite(&mut bytes, address("[::1]:1"), address("[::1]:2")).is_err());
}

#[test]
fn packet_ipv6_extension_header_is_walked_and_checksummed() {
    let original = fixture("ipv6_udp");
    let mut extended = original[..40].to_vec();
    extended[6] = 0;
    let length = u16::from_be_bytes([extended[4], extended[5]]) + 8;
    extended[4..6].copy_from_slice(&length.to_be_bytes());
    extended.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
    extended.extend_from_slice(&original[40..]);
    assert_eq!(packet::parse(&extended).unwrap().transport, 48);
    assert!(packet::checksums_valid(&extended).unwrap());
    extended[40] = 44;
    assert_eq!(packet::parse(&extended), Err(PacketError::Fragment));
}

#[test]
fn tcp_reset_acknowledges_sequence_payload_and_syn() {
    let original = fixture("ipv4_tcp");
    let response = packet::tcp_reset(&original).unwrap().unwrap();
    let meta = packet::parse(&response).unwrap();
    assert_eq!(meta.source, packet::parse(&original).unwrap().destination);
    assert_eq!(response[meta.transport + 13], 0x14);
    assert_eq!(
        u32::from_be_bytes(
            response[meta.transport + 8..meta.transport + 12]
                .try_into()
                .unwrap()
        ),
        106
    );
    assert!(packet::checksums_valid(&response).unwrap());
    assert!(packet::tcp_reset(&response).unwrap().is_none());
}

#[test]
fn tcp_reset_uses_ack_as_sequence_when_present() {
    let mut original = fixture("ipv6_tcp");
    original[53] = 0x10;
    original[48..52].copy_from_slice(&1234u32.to_be_bytes());
    let response = packet::tcp_reset(&original).unwrap().unwrap();
    assert_eq!(response[53], 4);
    assert_eq!(&response[44..48], &1234u32.to_be_bytes());
    assert!(packet::checksums_valid(&response).unwrap());
}

#[test]
fn udp_unreachable_contains_original_packet_and_valid_icmp_checksum() {
    for name in ["ipv4_udp", "ipv6_udp"] {
        let original = fixture(name);
        let response = packet::udp_unreachable(&original).unwrap();
        let start = if name.starts_with("ipv4") { 20 } else { 40 };
        assert_eq!(&response[start + 8..], original);
        if start == 20 {
            assert_eq!(response[20], 3);
            assert_eq!(packet::checksum(&response[..20]), 0);
            assert_eq!(packet::checksum(&response[20..]), 0);
        } else {
            assert_eq!(response[40], 1);
            let mut pseudo = response[8..40].to_vec();
            pseudo.extend_from_slice(&((response.len() - 40) as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 58]);
            pseudo.extend_from_slice(&response[40..]);
            assert_eq!(packet::checksum(&pseudo), 0);
        }
    }
}

#[test]
fn nat_bidirectional_restore_preserves_tcp_udp_and_ipv6() {
    let nat = NatSessionTable::new(8, 13080, 13081);
    for name in ["ipv4_udp", "ipv6_udp", "ipv4_tcp", "ipv6_tcp"] {
        let mut bytes = fixture(name);
        let meta = packet::parse(&bytes).unwrap();
        let session = nat.redirect(&mut bytes, 100, 0).unwrap();
        let redirected = packet::parse(&bytes).unwrap();
        assert_eq!(redirected.source, session.alias);
        assert_eq!(redirected.destination, session.relay);
        packet::rewrite(&mut bytes, session.relay, session.alias).unwrap();
        assert!(nat.restore(&mut bytes, 1).unwrap());
        let restored = packet::parse(&bytes).unwrap();
        assert_eq!(restored.source, meta.destination);
        assert_eq!(restored.destination, meta.source);
        assert!(packet::checksums_valid(&bytes).unwrap());
    }
}

#[test]
fn nat_udp_same_local_socket_different_destinations_gets_distinct_aliases() {
    let nat = NatSessionTable::new(4, 13080, 13081);
    let flow = FlowKey {
        protocol: Protocol::Udp,
        client: address("10.0.0.2:40000"),
        target: address("1.1.1.1:443"),
    };
    let first = nat.register(flow, 100, 0).unwrap();
    let second = nat
        .register(
            FlowKey {
                target: address("8.8.8.8:53"),
                ..flow
            },
            100,
            0,
        )
        .unwrap();
    assert_ne!(first.alias, second.alias);
    assert_eq!(
        nat.by_alias(Protocol::Udp, first.alias, 1)
            .unwrap()
            .flow
            .target,
        flow.target
    );
}

#[test]
fn nat_capacity_ownership_and_ttl_are_enforced() {
    let nat = NatSessionTable::new(1, 13080, 13081);
    let flow = FlowKey {
        protocol: Protocol::Udp,
        client: address("10.0.0.2:40000"),
        target: address("1.1.1.1:443"),
    };
    let session = nat.register(flow, 100, 0).unwrap();
    assert!(nat.register(flow, 101, 0).is_err());
    assert!(
        nat.register(
            FlowKey {
                target: address("8.8.8.8:53"),
                ..flow
            },
            100,
            0
        )
        .is_err()
    );
    assert_eq!(nat.evict(121, 1000, 120).unwrap(), 1);
    assert!(nat.by_alias(Protocol::Udp, session.alias, 122).is_none());
}

#[test]
fn nat_concurrent_registration_is_idempotent() {
    let nat = Arc::new(NatSessionTable::new(64, 13080, 13081));
    let flow = FlowKey {
        protocol: Protocol::Tcp,
        client: address("10.0.0.2:40000"),
        target: address("1.1.1.1:443"),
    };
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let nat = Arc::clone(&nat);
            std::thread::spawn(move || nat.register(flow, 100, 1).unwrap().alias)
        })
        .collect();
    let aliases: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(aliases.iter().all(|alias| *alias == aliases[0]));
    assert_eq!(nat.len(), 1);
}

#[test]
fn kill_switch_defaults_down_and_drops_only_selected_traffic() {
    let status = TunnelStatus::default();
    assert_eq!(status.get(), TunnelState::Down);
    for name in ["ipv4_udp", "ipv4_tcp", "ipv6_udp", "ipv6_tcp"] {
        let bytes = fixture(name);
        assert!(matches!(
            nat_engine::kill_switch(&bytes, true, status.get()).unwrap(),
            KillSwitchAction::DropWithReply(_)
        ));
        assert_eq!(
            nat_engine::kill_switch(&bytes, false, TunnelState::Down).unwrap(),
            KillSwitchAction::Forward
        );
        assert_eq!(
            nat_engine::kill_switch(&bytes, true, TunnelState::Connected).unwrap(),
            KillSwitchAction::Forward
        );
    }
    status.set(TunnelState::Reconnecting);
    assert_eq!(status.get(), TunnelState::Reconnecting);
}

#[test]
fn process_inheritance_handles_snapshot_order_and_pid_reuse() {
    let root = process(10, 1, 100, "C:/apps/launcher.exe");
    let child = process(11, 10, 101, "C:/apps/child.exe");
    let grandchild = process(12, 11, 102, "C:/apps/grandchild.exe");
    let mut tracker = ProcessTracker::new(vec![rule(true)], []).unwrap();
    tracker
        .refresh(&[grandchild.clone(), child.clone(), root])
        .unwrap();
    assert_eq!(tracker.tracked().count(), 3);
    tracker.refresh(&[child, grandchild]).unwrap();
    assert!(tracker.get(11).is_some());
    tracker
        .refresh(&[process(11, 1, 200, "C:/apps/other.exe")])
        .unwrap();
    assert!(tracker.get(11).is_none());
}

#[test]
fn process_child_policy_exclusions_and_parent_creation_are_enforced() {
    let processes = [
        process(10, 1, 100, "C:/apps/launcher.exe"),
        process(11, 10, 99, "C:/apps/child.exe"),
    ];
    let mut tracker = ProcessTracker::new(vec![rule(true)], []).unwrap();
    tracker.refresh(&processes).unwrap();
    assert!(tracker.get(11).is_none());
    let mut tracker = ProcessTracker::new(vec![rule(true)], [10]).unwrap();
    tracker.refresh(&processes).unwrap();
    assert_eq!(tracker.tracked().count(), 0);
    let mut tracker = ProcessTracker::new(vec![rule(false)], []).unwrap();
    tracker
        .refresh(&[
            processes[0].clone(),
            process(11, 10, 101, "C:/apps/child.exe"),
        ])
        .unwrap();
    assert_eq!(tracker.tracked().count(), 1);
}

#[test]
fn process_rule_combines_name_glob_and_hash_with_and() {
    use sha2::{Digest, Sha256};
    let dir = Directory::new();
    let image = dir.root.join("launcher.exe");
    std::fs::write(&image, b"image content").unwrap();
    let rule = ProcessRule {
        exe_name: Some("LAUNCHER.EXE".into()),
        path_glob: Some(
            format!(
                "{}/**/launcher.exe",
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).display()
            )
            .replace('\\', "/"),
        ),
        sha256: Some(hex::encode(Sha256::digest(b"image content"))),
        include_children: true,
    };
    let compiled = mtp_splitter::process_tracker::CompiledRule::new(rule).unwrap();
    assert!(compiled.matches(&image).unwrap());
    std::fs::write(&image, b"modified image").unwrap();
    assert!(!compiled.matches(&image).unwrap());
}

#[test]
fn process_rule_cache_is_bound_to_creation_time_and_rechecks_reused_pid() {
    use sha2::{Digest, Sha256};
    let dir = Directory::new();
    let image = dir.paths.resolve("runtime/cached-image.exe").unwrap();
    std::fs::write(&image, b"old image").unwrap();
    let rule = ProcessRule {
        exe_name: None,
        path_glob: None,
        sha256: Some(hex::encode(Sha256::digest(b"new image"))),
        include_children: true,
    };
    let mut tracker = ProcessTracker::new(vec![rule], []).unwrap();
    let first = ProcessIdentity {
        pid: 42,
        parent: 0,
        creation_time: 100,
        image: image.clone(),
    };
    tracker.refresh(std::slice::from_ref(&first)).unwrap();
    assert!(tracker.get(42).is_none());
    std::fs::remove_file(&image).unwrap();
    tracker.refresh(std::slice::from_ref(&first)).unwrap();
    assert!(tracker.get(42).is_none());
    std::fs::write(&image, b"new image").unwrap();
    let reused = ProcessIdentity {
        creation_time: 101,
        ..first
    };
    tracker.refresh(&[reused]).unwrap();
    assert!(tracker.get(42).unwrap().inherit);
}

#[test]
fn active_socket_tracks_wildcard_ambiguity_close_and_rebinding() {
    let sockets = ActiveSocketTable::default();
    let local = address("0.0.0.0:45000");
    let key = SocketKey {
        protocol: Protocol::Udp,
        local,
    };
    let owner = SocketOwner {
        endpoint_id: 1,
        pid: 100,
        creation_time: 1,
        close_after_ms: None,
    };
    sockets.register(key, owner).unwrap();
    assert_eq!(
        sockets.owner(Protocol::Udp, address("10.0.0.2:45000"), 0),
        Ownership::Known(100)
    );
    sockets
        .register(
            key,
            SocketOwner {
                endpoint_id: 2,
                pid: 200,
                ..owner
            },
        )
        .unwrap();
    assert_eq!(sockets.owner(Protocol::Udp, local, 0), Ownership::Ambiguous);
    sockets.close(2, 0).unwrap();
    sockets.evict(2001).unwrap();
    assert_eq!(
        sockets.owner(Protocol::Udp, local, 2001),
        Ownership::Known(100)
    );
    let new = SocketKey {
        local: address("10.0.0.2:45001"),
        ..key
    };
    sockets.register(new, owner).unwrap();
    assert_eq!(
        sockets.owner(Protocol::Udp, local, 2001),
        Ownership::Unknown
    );
    assert_eq!(
        sockets.owner(Protocol::Udp, new.local, 2001),
        Ownership::Known(100)
    );
}

#[test]
fn active_socket_concurrent_rebinding_close_and_eviction_finish_without_lock_inversion() {
    let table = Arc::new(ActiveSocketTable::default());
    let (sender, receiver) = std::sync::mpsc::channel();
    let mut tasks = Vec::new();
    for thread in 0..4u64 {
        let table = Arc::clone(&table);
        let sender = sender.clone();
        tasks.push(std::thread::spawn(move || {
            for iteration in 0..1000 {
                let endpoint = thread * 1000 + iteration;
                let key = SocketKey {
                    protocol: Protocol::Udp,
                    local: address("0.0.0.0:45000"),
                };
                table
                    .register(
                        key,
                        SocketOwner {
                            endpoint_id: endpoint,
                            pid: 100,
                            creation_time: 1,
                            close_after_ms: None,
                        },
                    )
                    .unwrap();
                table.close(endpoint, iteration).unwrap();
                table.evict(iteration + 2001).unwrap();
            }
            sender.send(()).unwrap();
        }));
    }
    for _ in 0..4 {
        receiver.recv_timeout(Duration::from_secs(10)).unwrap();
    }
    for task in tasks {
        task.join().unwrap();
    }
    table.evict(u64::MAX).unwrap();
    assert_eq!(
        table.owner(Protocol::Udp, address("10.0.0.2:45000"), u64::MAX),
        Ownership::Unknown
    );
}

#[test]
fn dns_rejects_response_only_flags_and_nonzero_request_rcode() {
    for flags in [0x8100u16, 0x0300, 0x0500, 0x0180, 0x0103, 0x0140] {
        let mut request = query("example.com", 1);
        request[2..4].copy_from_slice(&flags.to_be_bytes());
        assert!(
            fake_dns::parse_question(&request).is_err(),
            "잘못된 flags: {flags:04x}"
        );
    }
}

#[test]
fn protocol_target_supports_ipv4_ipv6_and_domain() {
    for target in [
        Target {
            address: TargetAddress::Ip("1.1.1.1".parse().unwrap()),
            port: 443,
        },
        Target {
            address: TargetAddress::Ip("2001:db8::1".parse().unwrap()),
            port: 443,
        },
        Target {
            address: TargetAddress::Domain("example.com".into()),
            port: 443,
        },
    ] {
        let encoded = target.encode().unwrap();
        let (decoded, length) = Target::decode(&encoded).unwrap();
        assert_eq!(decoded, target);
        assert_eq!(length, encoded.len());
        for length in 0..encoded.len() {
            assert!(Target::decode(&encoded[..length]).is_err());
        }
    }
}

struct TinyReads<T>(T);
impl<T: Read> Read for TinyReads<T> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let length = buffer.len().min(1);
        self.0.read(&mut buffer[..length])
    }
}

#[test]
fn protocol_frames_survive_single_byte_reads_and_coalescing() {
    let frames = [
        Frame {
            kind: FrameType::Hello,
            stream_id: 0,
            payload: Settings::default().encode().unwrap(),
        },
        Frame {
            kind: FrameType::TcpData,
            stream_id: 1,
            payload: b"payload".to_vec(),
        },
        Frame {
            kind: FrameType::UdpDatagram,
            stream_id: 3,
            payload: Vec::new(),
        },
    ];
    let mut bytes = Vec::new();
    for frame in &frames {
        frame.write(&mut bytes).unwrap();
    }
    let mut reader = TinyReads(Cursor::new(bytes));
    for frame in frames {
        assert_eq!(Frame::read(&mut reader).unwrap(), frame);
    }
}

#[test]
fn protocol_rejects_oversized_lengths_flags_and_stream_ids() {
    assert!(Frame::read(&mut Cursor::new(u32::MAX.to_be_bytes())).is_err());
    for frame in [
        Frame {
            kind: FrameType::Ping,
            stream_id: 1,
            payload: vec![0; 8],
        },
        Frame {
            kind: FrameType::TcpFin,
            stream_id: 2,
            payload: Vec::new(),
        },
        Frame {
            kind: FrameType::TcpData,
            stream_id: 1,
            payload: Vec::new(),
        },
    ] {
        assert!(frame.validate().is_err());
    }
    let frame = Frame {
        kind: FrameType::Ping,
        stream_id: 0,
        payload: vec![0; 8],
    };
    let mut bytes = Vec::new();
    frame.write(&mut bytes).unwrap();
    bytes[6] = 1;
    assert!(Frame::read(&mut Cursor::new(bytes)).is_err());
}

#[test]
fn protocol_datagram_limit_allows_empty_and_maximum() {
    for size in [0, 65507, 65508] {
        let frame = Frame {
            kind: FrameType::UdpDatagram,
            stream_id: 1,
            payload: vec![0; size],
        };
        assert_eq!(frame.validate().is_ok(), size <= 65507);
    }
}

#[test]
fn shared_snapshot_is_consistent_and_generates_kernel_filter() {
    let dir = Directory::new();
    let mut writer = SharedState::open(&dir.paths, true).unwrap();
    let reader = SharedState::open(&dir.paths, false).unwrap();
    let nat = NatSessionTable::new(2, 13080, 13081);
    nat.register(
        FlowKey {
            protocol: Protocol::Udp,
            client: address("10.0.0.2:45000"),
            target: address("8.8.8.8:53"),
        },
        100,
        1,
    )
    .unwrap();
    writer
        .publish(&nat.snapshot(), TunnelState::Connected, 500)
        .unwrap();
    let snapshot = reader.snapshot().unwrap();
    assert_eq!(snapshot.state, TunnelState::Connected);
    assert_eq!(snapshot.heartbeat_ms, 500);
    assert_eq!(snapshot.rows[0][1], 100);
    let filters = mtp_splitter::watchdog::flow_filters(&snapshot).unwrap();
    assert!(filters[0].contains("udp.SrcPort == 45000"));
    assert!(filters[0].contains("ip.SrcAddr == 10.0.0.2"));
}

#[test]
fn shared_snapshot_never_exposes_mixed_generation_under_writes() {
    let dir = Directory::new();
    let mut writer = SharedState::open(&dir.paths, true).unwrap();
    let reader = SharedState::open(&dir.paths, false).unwrap();
    let task = std::thread::spawn(move || {
        let nat = NatSessionTable::new(1, 13080, 13081);
        for value in 1..1000 {
            let flow = FlowKey {
                protocol: Protocol::Udp,
                client: address("10.0.0.2:45000"),
                target: address("8.8.8.8:53"),
            };
            let session = nat.register(flow, 100, value).unwrap();
            writer
                .publish(&[session], TunnelState::Connected, value)
                .unwrap();
        }
    });
    for _ in 0..1000 {
        if let Ok(snapshot) = reader.snapshot()
            && !snapshot.rows.is_empty()
        {
            assert_eq!(snapshot.rows[0][3], snapshot.heartbeat_ms);
        }
    }
    task.join().unwrap();
}

#[test]
fn watchdog_latches_on_pipe_loss_and_requires_explicit_release() {
    let now = Instant::now();
    let mut watchdog = WatchdogPolicy::new(now, Duration::from_secs(5)).unwrap();
    watchdog.ready(now);
    assert_eq!(watchdog.state(), GuardState::Protecting);
    watchdog.broken_pipe();
    watchdog.heartbeat(now);
    assert_eq!(watchdog.state(), GuardState::Latched);
    watchdog.release();
    assert_eq!(watchdog.state(), GuardState::Released);
}

#[test]
fn watchdog_timeout_is_not_undone_by_late_heartbeat() {
    let now = Instant::now();
    let mut watchdog = WatchdogPolicy::new(now, Duration::from_secs(5)).unwrap();
    watchdog.ready(now);
    watchdog.tick(now + Duration::from_secs(6));
    watchdog.heartbeat(now + Duration::from_secs(7));
    assert_eq!(watchdog.state(), GuardState::Latched);
}

#[test]
fn paths_reject_traversal_and_atomic_write_replaces_existing_file() {
    let dir = Directory::new();
    for path in ["../outside", "config/../outside", "/absolute", ""] {
        assert!(dir.paths.resolve(path).is_err());
    }
    dir.paths
        .atomic_write("runtime/cache.json", b"first")
        .unwrap();
    dir.paths
        .atomic_write("runtime/cache.json", b"second")
        .unwrap();
    assert_eq!(
        std::fs::read(dir.paths.resolve("runtime/cache.json").unwrap()).unwrap(),
        b"second"
    );
}

#[test]
fn log_size_rotation_retains_limited_history() {
    let dir = Directory::new();
    let mut writer = mtp_splitter::logging::LogWriter::new(&dir.paths, 1024, 2).unwrap();
    for value in 0..8 {
        writer.write_all(&vec![b'a' + value; 600]).unwrap();
    }
    writer.flush().unwrap();
    assert_eq!(
        std::fs::read(dir.paths.resolve("logs/tunnel.log").unwrap()).unwrap(),
        vec![b'h'; 600]
    );
    assert!(dir.paths.resolve("logs/tunnel.log.2").unwrap().is_file());
    assert!(!dir.paths.resolve("logs/tunnel.log.3").unwrap().exists());
}

#[test]
fn server_configuration_rejects_mismatch_and_unknown_fields() {
    let mut config: ServerConfig =
        serde_json::from_str(include_str!("../examples/config/server.json")).unwrap();
    config.validate().unwrap();
    config.endpoint_ip().unwrap();
    config.tls_domain = "other.example".into();
    assert!(config.validate().is_err());
    let mut config: serde_json::Value =
        serde_json::from_str(include_str!("../examples/config/server.json")).unwrap();
    config["unexpected"] = true.into();
    assert!(serde_json::from_value::<ServerConfig>(config).is_err());
}

#[cfg(windows)]
#[test]
fn windows_process_query_resolves_current_executable_and_creation_time() {
    let process = mtp_splitter::platform::processes::identity(std::process::id(), 0).unwrap();
    assert!(process.image.is_absolute());
    assert!(process.creation_time > 0);
}

#[cfg(windows)]
#[test]
fn windivert_socket_addresses_use_host_words_in_reverse_order() {
    assert_eq!(
        mtp_splitter::platform::divert::decode_ip([0x01020304, 0xffff, 0, 0]),
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
    );
    assert_eq!(
        mtp_splitter::platform::divert::decode_ip([1, 0, 0, 0]),
        "::1".parse::<IpAddr>().unwrap()
    );
}
