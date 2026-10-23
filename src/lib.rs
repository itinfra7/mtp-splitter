//! 이식 가능한 패킷·DNS·전송 코어와 Windows 어댑터를 제공한다.
//! 네트워크 계층에서 프로세스 식별이 불가능한 한계를 보안 보장으로 숨기지 않는다.

pub mod client_bundle;
pub mod config;
pub mod fake_dns;
pub mod gateway;
pub mod gateway_wire;
pub mod logging;
pub mod mtproto_core;
pub mod nat_engine;
pub mod packet;
pub mod packet_router;
pub mod paths;
#[cfg(windows)]
pub mod platform;
pub mod process_tracker;
pub mod protocol;
pub mod relay;
pub mod shared_state;
pub mod transport;
pub mod watchdog;
