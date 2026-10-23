//! 실제 DLL의 필터·체크섬 ABI와 선택적인 비포착 커널 핸들을 검사한다.

use super::divert::{Address, DivertApi};
use crate::{packet, paths::AppPaths};
use anyhow::{Result, ensure};

pub fn check(paths: &AppPaths, kernel: bool, nat: bool) -> Result<()> {
    let _lock = if kernel || nat {
        Some(paths.lock()?)
    } else {
        None
    };
    let api = DivertApi::load(paths)?;
    for (filter, layer) in [
        ("outbound and (tcp or udp)", 0),
        (
            "event == BIND or event == CONNECT or event == LISTEN or event == CLOSE",
            3,
        ),
        (
            "outbound and tcp and tcp.SrcPort == 50000 and ip.SrcAddr == 10.0.0.2",
            0,
        ),
    ] {
        api.validate_filter(filter, layer)?;
    }
    ensure!(
        api.validate_filter("outbound and (", 0).is_err(),
        "잘못된 필터를 수락했습니다"
    );
    let mut count = 0;
    for (source, target) in [
        ("10.0.0.2:50000", "8.8.8.8:53"),
        ("[2001:db8::2]:50000", "[2001:db8::8]:53"),
    ] {
        for payload in [&[][..], &b"abcde"[..], &[0xa5; 1473][..]] {
            let expected = packet::udp(source.parse()?, target.parse()?, payload)?;
            let meta = packet::parse(&expected)?;
            let mut actual = expected.clone();
            if !meta.ipv6 {
                actual[10..12].fill(0);
            }
            actual[meta.transport + 6..meta.transport + 8].fill(0);
            let mut address = Address::default();
            address.set_outbound(true);
            address.bits |= u32::from(meta.ipv6) << 20;
            api.recalculate(&mut actual, &mut address)?;
            ensure!(actual == expected, "DLL과 Rust의 체크섬이 다릅니다");
            ensure!(
                api.matches("outbound and udp.DstPort == 53", &actual, &address)?,
                "DNS 필터가 일치하지 않습니다"
            );
            ensure!(
                !api.matches("inbound or tcp", &actual, &address)?,
                "다른 필터가 잘못 일치했습니다"
            );
            count += 1;
        }
    }
    println!("앱 bin의 WinDivert DLL 로딩·필터 검증·IPv4/IPv6 UDP 체크섬 비교 {count}건 성공");
    let kernel_result = (|| -> Result<()> {
        if kernel || nat {
            // false 필터는 실제 트래픽을 포착하지 않는다. 핸들을 닫으면 DLL의 정상 수명 주기를 따른다.
            let network = api.open("false", 0, 0, 0x1 | 0x4)?;
            let socket = api.open("false", 3, 0, 0x1 | 0x4)?;
            println!(
                "비포착 NETWORK·SOCKET 커널 핸들 생성 성공: {}.{}",
                network.parameter(3)?,
                socket.parameter(4)?
            );
            ensure!(
                super::driver_service::cleanup_idle(paths, &api)?
                    == super::driver_service::CleanupResult::InUse,
                "사용 중인 핸들의 보호 검증 실패"
            );
            ensure!(
                network.parameter(3)? == 2 && socket.parameter(3)? == 2,
                "정리 검사가 사용 중인 핸들을 중단했습니다"
            );
        } else {
            println!("커널 드라이버 로드·패킷 포착은 수행하지 않았습니다");
        }
        if nat {
            super::nat_probe::udp(&api)?;
            super::nat_probe::tcp(&api)?;
            super::nat_probe::reject_when_down(&api)?;
        }
        Ok(())
    })();
    let cleanup_result = if kernel || nat {
        super::driver_service::cleanup_idle(paths, &api).map(|_| ())
    } else {
        Ok(())
    };
    if let Err(error) = &cleanup_result {
        eprintln!("진단 후 드라이버 정리 실패: {error:#}");
    }
    kernel_result?;
    cleanup_result?;
    Ok(())
}
