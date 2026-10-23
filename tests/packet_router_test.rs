//! 소유권 확인 전 보류, PID 재사용 차단과 실제 주입 방향 결정을 검증한다.

use mtp_splitter::{
    nat_engine::{NatSessionTable, TunnelState, TunnelStatus},
    packet::{self, Protocol},
    packet_router::{Decision, DropReason, NetworkPath, PacketRouter},
    process_tracker::{ActiveSocketTable, ProcessIdentity, SocketKey, SocketOwner},
};
use std::sync::Arc;

fn fixture(name: &str) -> Vec<u8> {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/packets.json")).unwrap();
    hex::decode(fixtures[name].as_str().unwrap()).unwrap()
}
fn process(creation_time: u64) -> ProcessIdentity {
    ProcessIdentity {
        pid: 42,
        parent: 0,
        creation_time,
        image: "app.exe".into(),
    }
}
fn router(capacity: usize, excluded: &[u32]) -> PacketRouter {
    PacketRouter::new(
        Arc::new(NatSessionTable::new(capacity, 17001, 17002)),
        Arc::new(ActiveSocketTable::default()),
        Arc::new(TunnelStatus::default()),
        excluded.iter().copied(),
    )
}
fn register(router: &PacketRouter, packet: &[u8], tracked: bool) {
    let meta = packet::parse(packet).unwrap();
    router
        .replace_processes(&[process(100)], if tracked { vec![42] } else { vec![] })
        .unwrap();
    router
        .sockets
        .register(
            SocketKey {
                protocol: meta.protocol,
                local: meta.source,
            },
            SocketOwner {
                endpoint_id: 1,
                pid: 42,
                creation_time: 100,
                close_after_ms: None,
            },
        )
        .unwrap();
}
fn path() -> NetworkPath {
    NetworkPath {
        interface: 7,
        sub_interface: 3,
    }
}

#[test]
fn loopback_responses_and_kill_switch_replies_keep_outbound_delivery() {
    for source in ["127.0.0.1:45000", "[::1]:45000"] {
        let target = if source.starts_with('[') {
            "[::1]:53"
        } else {
            "127.0.0.1:53"
        };
        let original = packet::udp(
            source.parse().unwrap(),
            target.parse().unwrap(),
            b"loopback",
        )
        .unwrap();
        let router = router(10, &[]);
        register(&router, &original, true);
        assert!(matches!(
            router.decide(&original, true, path(), 0),
            Decision::Inject { outbound: true, .. }
        ));
        router.status.set(TunnelState::Connected);
        let Decision::Inject { mut packet, .. } = router.decide(&original, true, path(), 1) else {
            panic!("루프백 NAT 실패");
        };
        let meta = packet::parse(&packet).unwrap();
        packet::rewrite(&mut packet, meta.destination, meta.source).unwrap();
        let Decision::Inject {
            packet, outbound, ..
        } = router.decide(&packet, true, path(), 2)
        else {
            panic!("루프백 응답 복원 실패");
        };
        assert!(outbound);
        let meta = packet::parse(&packet).unwrap();
        assert_eq!(meta.source, target.parse().unwrap());
        assert_eq!(meta.destination, source.parse().unwrap());
    }
}

#[test]
fn unknown_owner_is_held_without_direct_fallback() {
    let router = router(10, &[]);
    router.status.set(TunnelState::Connected);
    let packet = fixture("ipv4_udp");
    assert_eq!(
        router.decide(&packet, true, path(), 0),
        Decision::AwaitOwnership
    );
    assert_eq!(router.decide(&packet, false, path(), 0), Decision::Pass);
    register(&router, &packet, false);
    assert_eq!(router.decide(&packet, true, path(), 1), Decision::Pass);
}

#[test]
fn tracked_tcp_udp_both_families_redirect_and_restore_original_interface() {
    for name in ["ipv4_tcp", "ipv4_udp", "ipv6_tcp", "ipv6_udp"] {
        let router = router(10, &[]);
        router.status.set(TunnelState::Connected);
        let original = fixture(name);
        let meta = packet::parse(&original).unwrap();
        register(&router, &original, true);
        let Decision::Inject {
            mut packet,
            outbound,
            path: output_path,
        } = router.decide(&original, true, path(), 0)
        else {
            panic!("추적 패킷을 NAT로 보내지 않았습니다")
        };
        assert!(outbound);
        assert_eq!(output_path, NetworkPath::default());
        assert!(packet::checksums_valid(&packet).unwrap());
        let redirected = packet::parse(&packet).unwrap();
        assert!(redirected.source.ip().is_loopback() && redirected.destination.ip().is_loopback());
        packet::rewrite(&mut packet, redirected.destination, redirected.source).unwrap();
        let Decision::Inject {
            packet,
            outbound,
            path: output_path,
        } = router.decide(
            &packet,
            true,
            NetworkPath {
                interface: 1,
                sub_interface: 0,
            },
            1,
        )
        else {
            panic!("릴레이 응답을 역변환하지 않았습니다")
        };
        assert!(!outbound);
        assert_eq!(output_path, path());
        let restored = packet::parse(&packet).unwrap();
        assert_eq!(restored.source, meta.destination);
        assert_eq!(restored.destination, meta.source);
        assert!(packet::checksums_valid(&packet).unwrap());
    }
}

#[test]
fn down_and_reconnecting_inject_local_failure_without_creating_nat() {
    for state in [TunnelState::Down, TunnelState::Reconnecting] {
        for name in ["ipv4_tcp", "ipv4_udp", "ipv6_tcp", "ipv6_udp"] {
            let router = router(10, &[]);
            router.status.set(state);
            let original = fixture(name);
            register(&router, &original, true);
            let Decision::Inject {
                packet: reply,
                outbound,
                path: reply_path,
            } = router.decide(&original, true, path(), 0)
            else {
                panic!("단절 시 실패 응답을 만들지 않았습니다")
            };
            assert!(!outbound);
            assert_eq!(reply_path, path());
            assert!(router.nat.is_empty());
            if name.ends_with("tcp") {
                let meta = packet::parse(&reply).unwrap();
                assert_ne!(reply[meta.transport + 13] & 4, 0);
                assert!(packet::checksums_valid(&reply).unwrap());
            } else if name.starts_with("ipv4") {
                assert_eq!(reply[9], 1);
                assert_eq!(&reply[20..22], &[3, 13]);
                assert_eq!(packet::checksum(&reply[20..]), 0);
            } else {
                assert_eq!(reply[6], 58);
                assert_eq!(&reply[40..42], &[1, 1]);
            }
        }
    }
}

#[test]
fn excluded_process_cannot_be_redirected_by_a_rule() {
    let router = router(10, &[42]);
    let packet = fixture("ipv4_tcp");
    register(&router, &packet, true);
    assert_eq!(router.decide(&packet, true, path(), 0), Decision::Pass);
}

#[test]
fn old_socket_identity_does_not_authorize_reused_pid() {
    let router = router(10, &[]);
    let packet = fixture("ipv4_tcp");
    register(&router, &packet, true);
    router.replace_processes(&[process(101)], []).unwrap();
    assert_eq!(
        router.decide(&packet, true, path(), 0),
        Decision::Drop(DropReason::StaleOwner)
    );
    router.replace_processes(&[], []).unwrap();
    assert_eq!(
        router.decide(&packet, true, path(), 0),
        Decision::AwaitOwnership
    );
}

#[test]
fn same_pid_with_different_creation_times_is_ambiguous() {
    let router = router(10, &[]);
    let packet = fixture("ipv4_udp");
    let meta = packet::parse(&packet).unwrap();
    register(&router, &packet, true);
    router
        .sockets
        .register(
            SocketKey {
                protocol: Protocol::Udp,
                local: meta.source,
            },
            SocketOwner {
                endpoint_id: 2,
                pid: 42,
                creation_time: 101,
                close_after_ms: None,
            },
        )
        .unwrap();
    assert_eq!(
        router.decide(&packet, true, path(), 0),
        Decision::Drop(DropReason::AmbiguousOwner)
    );
}

#[test]
fn exhausted_nat_never_passes_tracked_packets() {
    let router = router(0, &[]);
    router.status.set(TunnelState::Connected);
    let packet = fixture("ipv4_tcp");
    register(&router, &packet, true);
    assert_eq!(
        router.decide(&packet, true, path(), 0),
        Decision::Drop(DropReason::NatFailure)
    );
}

#[test]
fn malformed_and_fragmented_packets_are_dropped() {
    let router = router(10, &[]);
    assert_eq!(
        router.decide(&[], true, path(), 0),
        Decision::Drop(DropReason::Malformed)
    );
    let mut fragment = fixture("ipv4_udp");
    fragment[6] |= 0x20;
    assert_eq!(
        router.decide(&fragment, true, path(), 0),
        Decision::Drop(DropReason::Malformed)
    );
}

#[test]
fn invalid_process_snapshot_does_not_replace_previous_state() {
    let router = router(10, &[]);
    let packet = fixture("ipv4_tcp");
    register(&router, &packet, false);
    assert!(
        router
            .replace_processes(&[process(100), process(101)], [])
            .is_err()
    );
    assert!(router.replace_processes(&[process(100)], [999]).is_err());
    assert_eq!(router.decide(&packet, true, path(), 0), Decision::Pass);
}

#[test]
fn reused_pid_cannot_adopt_previous_nat_generation() {
    let router = router(10, &[]);
    let packet = fixture("ipv4_udp");
    register(&router, &packet, true);
    router.status.set(TunnelState::Connected);
    assert!(matches!(
        router.decide(&packet, true, path(), 0),
        Decision::Inject { .. }
    ));
    router.replace_processes(&[process(101)], [42]).unwrap();
    let meta = packet::parse(&packet).unwrap();
    router
        .sockets
        .register(
            SocketKey {
                protocol: meta.protocol,
                local: meta.source,
            },
            SocketOwner {
                endpoint_id: 1,
                pid: 42,
                creation_time: 101,
                close_after_ms: None,
            },
        )
        .unwrap();
    assert_eq!(
        router.decide(&packet, true, path(), 1),
        Decision::Drop(DropReason::StaleOwner)
    );
    router.evict(1000, 100, 100).unwrap();
    assert!(matches!(
        router.decide(&packet, true, path(), 1001),
        Decision::Inject { .. }
    ));
}

#[test]
fn delayed_relay_response_is_not_injected_into_reused_pid() {
    let router = router(10, &[]);
    let original = fixture("ipv4_udp");
    register(&router, &original, true);
    router.status.set(TunnelState::Connected);
    let Decision::Inject { mut packet, .. } = router.decide(&original, true, path(), 0) else {
        panic!("NAT 등록 실패")
    };
    let meta = packet::parse(&packet).unwrap();
    packet::rewrite(&mut packet, meta.destination, meta.source).unwrap();
    router.replace_processes(&[process(101)], [42]).unwrap();
    assert_eq!(
        router.decide(&packet, true, path(), 1),
        Decision::Drop(DropReason::StaleOwner)
    );
}
