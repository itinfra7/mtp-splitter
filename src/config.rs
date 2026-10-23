//! 비밀값을 디버그 출력하지 않는 엄격한 JSON 설정을 읽는다.

use crate::{mtproto_core::ProxySecret, paths::AppPaths};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{fs, net::IpAddr};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelMode {
    ExtendedSocksOverMtproto,
    StandardDc,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub secret_hex: String,
    pub tls_domain: String,
    pub tunnel_mode: TunnelMode,
    #[serde(default = "default_dc")]
    pub dc_id: i16,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}
fn default_dc() -> i16 {
    2
}
fn default_timeout() -> u64 {
    10
}

impl ServerConfig {
    pub fn validate(&self) -> Result<ProxySecret> {
        if self.host.is_empty() || self.host.len() > 253 || self.port == 0 {
            bail!("서버 주소 또는 포트가 잘못됐습니다");
        }
        if !(1..=120).contains(&self.timeout_seconds) {
            bail!("연결 제한 시간은 1~120초여야 합니다");
        }
        if self.dc_id == 0 {
            bail!("DC 번호 0은 사용할 수 없습니다");
        }
        let secret = ProxySecret::parse(&self.secret_hex)?;
        if !secret.domain().eq_ignore_ascii_case(&self.tls_domain) {
            bail!("비밀값의 도메인과 tls_domain이 다릅니다");
        }
        Ok(secret)
    }

    /// 프록시 호스트 자체의 DNS 부트스트랩 누수를 막기 위해 IP 사용을 별도로 검증한다.
    pub fn endpoint_ip(&self) -> Result<IpAddr> {
        self.host
            .parse()
            .context("누수 없는 부트스트랩에는 프록시 IP 리터럴이 필요합니다")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessRule {
    #[serde(default)]
    pub exe_name: Option<String>,
    #[serde(default)]
    pub path_glob: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub include_children: bool,
}

pub fn load(paths: &AppPaths) -> Result<(ServerConfig, Vec<ProcessRule>)> {
    let server = load_server(paths)?;
    let rules = load_rules(paths)?;
    if rules.is_empty() {
        bail!("최소 하나의 대상 프로세스 규칙이 필요합니다");
    }
    Ok((server, rules))
}

pub fn load_server(paths: &AppPaths) -> Result<ServerConfig> {
    let server: ServerConfig =
        serde_json::from_slice(&fs::read(paths.resolve("config/server.json")?)?)?;
    server.validate()?;
    Ok(server)
}

pub fn load_rules(paths: &AppPaths) -> Result<Vec<ProcessRule>> {
    let rules: Vec<ProcessRule> =
        serde_json::from_slice(&fs::read(paths.resolve("config/rules.json")?)?)?;
    Ok(rules)
}
