//! 서버가 발급한 비공개 ZIP을 제한된 크기로 검사하고 앱 내부 구성으로 가져온다.
//! 인증서를 메모리에서 검증한 뒤 교체하며 디스크 백업과 임시 개인키를 만들지 않는다.

use crate::{config::ServerConfig, paths::AppPaths, transport::SecurityConfig};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Read},
    path::{Component, Path},
};

const FILE_LIMIT: u64 = 128 * 1024;
const ARCHIVE_LIMIT: u64 = 2 * 1024 * 1024;
const REQUIRED: [&str; 5] = [
    "server.json",
    "security.json",
    "gateway-ca.pem",
    "client.pem",
    "client-key.pem",
];

pub struct ClientBundle {
    pub server: ServerConfig,
    pub security: SecurityConfig,
    files: BTreeMap<String, zeroize::Zeroizing<Vec<u8>>>,
}
impl ClientBundle {
    pub fn read(path: &Path) -> Result<Self> {
        let file = fs::File::open(path).context("서버 ZIP을 열지 못했습니다")?;
        ensure!(
            file.metadata()?.len() <= ARCHIVE_LIMIT,
            "서버 ZIP이 2MiB를 초과합니다"
        );
        let mut bytes = Vec::new();
        file.take(ARCHIVE_LIMIT + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= ARCHIVE_LIMIT as usize,
            "서버 ZIP이 크기 제한을 초과했습니다"
        );
        Self::from_bytes(bytes)
    }
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        ensure!(
            bytes.len() <= ARCHIVE_LIMIT as usize,
            "서버 ZIP 크기가 잘못됐습니다"
        );
        let mut archive = zip::ZipArchive::new(Cursor::new(zeroize::Zeroizing::new(bytes)))
            .map_err(|_| anyhow::anyhow!("올바른 ZIP 형식이 아닙니다"))?;
        ensure!(archive.len() <= 32, "서버 ZIP의 항목 수가 너무 많습니다");
        let mut files = BTreeMap::new();
        let mut config_root = None;
        for index in 0..archive.len() {
            let mut entry = archive
                .by_index(index)
                .map_err(|_| anyhow::anyhow!("ZIP 항목을 읽지 못했습니다"))?;
            ensure!(
                !entry
                    .name()
                    .map_err(|_| anyhow::anyhow!("ZIP 이름 인코딩 오류"))?
                    .contains('\\'),
                "ZIP에 허용하지 않는 경로가 있습니다"
            );
            let path = entry
                .enclosed_name()
                .context("ZIP 경로가 안전하지 않습니다")?;
            ensure!(
                path.components().all(|c| matches!(c, Component::Normal(_))),
                "ZIP에 상위 경로 참조가 있습니다"
            );
            ensure!(
                entry.unix_mode().is_none_or(|m| m & 0o170000 != 0o120000),
                "ZIP의 심볼릭 링크는 허용하지 않습니다"
            );
            if entry.is_dir() {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .context("ZIP 파일 이름이 잘못됐습니다")?;
            ensure!(
                REQUIRED.contains(&name),
                "ZIP에 허용하지 않는 구성 파일이 있습니다"
            );
            let parent = path.parent().context("ZIP의 config 폴더가 없습니다")?;
            ensure!(
                parent.file_name().is_some_and(|s| s == "config"),
                "ZIP 항목은 config 폴더 안에 있어야 합니다"
            );
            ensure!(
                config_root.as_ref().is_none_or(|p| p == parent),
                "ZIP 안에 서로 다른 config 폴더가 있습니다"
            );
            config_root = Some(parent.to_path_buf());
            ensure!(
                entry.size() <= FILE_LIMIT,
                "ZIP 구성 항목이 크기 제한을 초과했습니다"
            );
            let name = name.to_owned();
            let mut content = zeroize::Zeroizing::new(Vec::new());
            entry
                .by_ref()
                .take(FILE_LIMIT + 1)
                .read_to_end(&mut content)
                .map_err(|_| anyhow::anyhow!("ZIP 내용 또는 CRC 검사 실패"))?;
            ensure!(
                content.len() <= FILE_LIMIT as usize,
                "ZIP 구성 항목이 너무 큽니다"
            );
            ensure!(
                files.insert(name, content).is_none(),
                "ZIP에 중복 구성 파일이 있습니다"
            );
        }
        ensure!(
            files.len() == REQUIRED.len(),
            "서버 설정·인증서·개인키 다섯 파일이 모두 필요합니다"
        );
        // serde 오류 원문에는 입력 비밀값이 포함될 수 있어 외부 오류에 붙이지 않는다.
        let server: ServerConfig = serde_json::from_slice(&files["server.json"])
            .map_err(|_| anyhow::anyhow!("서버 설정 JSON 형식이 잘못됐습니다"))?;
        server
            .validate()
            .map_err(|_| anyhow::anyhow!("서버 주소·포트·비밀값·도메인을 확인하십시오"))?;
        server
            .endpoint_ip()
            .map_err(|_| anyhow::anyhow!("서버 부트스트랩 주소는 IP 리터럴이어야 합니다"))?;
        let mut security: SecurityConfig = serde_json::from_slice(&files["security.json"])
            .map_err(|_| anyhow::anyhow!("보안 설정 JSON 형식이 잘못됐습니다"))?;
        ensure!(
            security.ca_certificate == "config/gateway-ca.pem"
                && security.client_certificate == "config/client.pem"
                && security.client_key == "config/client-key.pem",
            "인증서 경로가 패키지 내부의 표준 경로와 다릅니다"
        );
        // 가져온 인증서는 별도 하위 폴더에 모아 운영 파일과 공개 샘플의 혼동을 막는다.
        security.ca_certificate = "config/imported/gateway-ca.pem".into();
        security.client_certificate = "config/imported/client.pem".into();
        security.client_key = "config/imported/client-key.pem".into();
        Ok(Self {
            server,
            security,
            files,
        })
    }
    pub fn install(&self, paths: &AppPaths) -> Result<()> {
        let _lock = paths
            .lock()
            .context("실행을 멈춘 뒤 서버 구성을 가져오십시오")?;
        #[cfg(windows)]
        let _guard_lock = crate::platform::guard_lock::root_lock(paths)?;
        self.security
            .tls_config_from_pem(
                self.files["gateway-ca.pem"].as_slice(),
                self.files["client.pem"].as_slice(),
                self.files["client-key.pem"].as_slice(),
            )
            .context("서버 인증서·개인키 검사 실패")?;
        fs::create_dir_all(paths.resolve("config/imported")?)?;
        let mut updates: Vec<(String, zeroize::Zeroizing<Vec<u8>>)> = REQUIRED[2..]
            .iter()
            .map(|name| (format!("config/imported/{name}"), self.files[*name].clone()))
            .collect();
        updates.push((
            "config/security.json".into(),
            zeroize::Zeroizing::new(serde_json::to_vec_pretty(&self.security)?),
        ));
        updates.push((
            "config/server.json".into(),
            zeroize::Zeroizing::new(serde_json::to_vec_pretty(&self.server)?),
        ));
        let mut previous = Vec::new();
        for (relative, _) in &updates {
            let prior = match fs::read(paths.resolve(relative)?) {
                Ok(bytes) => Some(zeroize::Zeroizing::new(bytes)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e.into()),
            };
            previous.push(prior);
        }
        for (index, (relative, bytes)) in updates.iter().enumerate() {
            if let Err(error) = paths.atomic_write(relative, bytes) {
                for ((relative, _), prior) in updates[..index].iter().zip(&previous) {
                    let rollback = match prior {
                        Some(bytes) => paths.atomic_write(relative, bytes),
                        None => fs::remove_file(paths.resolve(relative)?).map_err(Into::into),
                    };
                    if let Err(rollback) = rollback {
                        tracing::error!(%rollback, "이전 서버 구성 복원 실패");
                    }
                }
                return Err(error).context("서버 구성 교체 실패, 이전 구성을 복원했습니다");
            }
        }
        remove_config_backups(paths)
            .context("설정은 적용됐지만 이전 설정 백업을 삭제하지 못했습니다")?;
        tracing::info!("비공개 서버 구성을 로컬 앱 폴더로 가져왔습니다");
        Ok(())
    }
}

/// 앱이 관리하는 서버 구성과 인증서만 지운다. 프로세스 규칙과 원본 ZIP은 보존한다.
pub fn clear_server(paths: &AppPaths) -> Result<()> {
    let _lock = paths
        .lock()
        .context("종료 · 차단 해제 후 서버 설정을 삭제하십시오")?;
    #[cfg(windows)]
    let _guard_lock = crate::platform::guard_lock::root_lock(paths)?;
    let managed = [
        "config/server.json",
        "config/security.json",
        "config/imported/client-key.pem",
        "config/imported/client.pem",
        "config/imported/gateway-ca.pem",
        "config/client-key.pem",
        "config/client.pem",
        "config/gateway-ca.pem",
    ];
    // 삭제를 시작하기 전에 모든 대상의 상위 경로를 검사한다.
    let targets = managed
        .iter()
        .map(|path| paths.resolve(path))
        .collect::<Result<Vec<_>>>()?;
    for path in targets {
        remove_file_if_present(&path)?;
    }
    remove_config_backups(paths)?;
    tracing::info!("서버 설정을 삭제했습니다");
    Ok(())
}

fn remove_file_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// 이전 버전이 만든 정확한 다섯 백업 파일만 제거하며 다른 자료는 건드리지 않는다.
fn remove_config_backups(paths: &AppPaths) -> Result<()> {
    let root = paths.resolve("runtime/backups")?;
    let entries = match fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some((time, nonce)) = name
            .strip_prefix("config-")
            .and_then(|value| value.split_once('-'))
        else {
            continue;
        };
        if time.parse::<u128>().is_err()
            || nonce.parse::<u64>().is_err()
            || !entry.file_type()?.is_dir()
        {
            continue;
        }
        let relative = format!("runtime/backups/{name}");
        let directory = paths.resolve(&relative)?;
        let targets = (0..5)
            .map(|index| paths.resolve(format!("{relative}/{index}.backup")))
            .collect::<Result<Vec<_>>>()?;
        for target in targets {
            remove_file_if_present(&target)?;
        }
        match fs::remove_dir(directory) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
