//! 공개 테스트 인증서로 비공개 패키지의 경로·크기·인증서·교체·정보 노출 경계를 검사한다.

use mtp_splitter::{client_bundle::ClientBundle, paths::AppPaths, transport::SecurityConfig};
use std::{
    fs,
    io::{Cursor, Write},
    path::PathBuf,
};

fn entries() -> Vec<(String, Vec<u8>)> {
    let security = serde_json::json!({"transport":"mtp_tcp_v1","server_name":"gateway.test","ca_file":"config/gateway-ca.pem","certificate_file":"config/client.pem","private_key_file":"config/client-key.pem","mux_version":1,"zero_rtt":false});
    vec![
        (
            "client/config/server.json".into(),
            include_bytes!("../examples/config/server.json").to_vec(),
        ),
        (
            "client/config/security.json".into(),
            serde_json::to_vec(&security).unwrap(),
        ),
        (
            "client/config/gateway-ca.pem".into(),
            include_bytes!("fixtures/test-ca.pem").to_vec(),
        ),
        (
            "client/config/client.pem".into(),
            include_bytes!("fixtures/test-client.pem").to_vec(),
        ),
        (
            "client/config/client-key.pem".into(),
            include_bytes!("fixtures/test-client-key.pem").to_vec(),
        ),
    ]
}
fn archive(entries: Vec<(String, Vec<u8>)>) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in entries {
        zip.start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(&bytes).unwrap();
    }
    zip.finish().unwrap().into_inner()
}
struct Directory {
    paths: AppPaths,
}
impl Directory {
    fn new() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("runtime/tmp")
            .join(format!(
                "bundle-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
        fs::create_dir_all(&root).unwrap();
        let paths = AppPaths::new(root).unwrap();
        paths.prepare().unwrap();
        Self { paths }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .unwrap();
        let root = self.paths.root().canonicalize().unwrap();
        assert!(root.starts_with(workspace.join("runtime/tmp")));
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn issued_bundle_is_validated_without_disk_backup_or_staged_private_keys() {
    let dir = Directory::new();
    fs::write(
        dir.paths.resolve("config/server.json").unwrap(),
        b"previous-config",
    )
    .unwrap();
    let bundle = ClientBundle::from_bytes(archive(entries())).unwrap();
    bundle.install(&dir.paths).unwrap();
    let security = SecurityConfig::load(&dir.paths).unwrap();
    assert_eq!(security.protocol_version, 1);
    assert_eq!(security.transport.as_deref(), Some("mtp_tcp_v1"));
    assert!(security.tls_config(&dir.paths).is_ok());
    assert!(
        dir.paths
            .resolve("config/imported/client-key.pem")
            .unwrap()
            .is_file()
    );
    assert!(!dir.paths.resolve("runtime/backups").unwrap().exists());
    assert!(
        !fs::read_dir(dir.paths.resolve("runtime").unwrap())
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("import-"))
    );
}

#[test]
fn malformed_secret_is_never_echoed_in_import_error() {
    let marker = "private-leak-sentinel-please-do-not-print";
    let mut files = entries();
    let mut server: serde_json::Value = serde_json::from_slice(&files[0].1).unwrap();
    server["secret_hex"] = marker.into();
    files[0].1 = serde_json::to_vec(&server).unwrap();
    let error = ClientBundle::from_bytes(archive(files)).err().unwrap();
    assert!(!format!("{error:#}").contains(marker));
}

#[test]
fn traversal_extra_entries_and_oversized_members_are_rejected() {
    for name in [
        "../client/config/client-key.pem",
        "client/config/extra.txt",
        "client\\config\\client-key.pem",
    ] {
        let mut files = entries();
        files.push((name.into(), b"reject".to_vec()));
        assert!(ClientBundle::from_bytes(archive(files)).is_err());
    }
    let mut files = entries();
    files[4].1 = vec![b'A'; 128 * 1024 + 1];
    assert!(ClientBundle::from_bytes(archive(files)).is_err());
    let mut files = entries();
    files.pop();
    assert!(ClientBundle::from_bytes(archive(files)).is_err());
}

#[test]
fn zero_rtt_external_key_path_and_mismatched_key_never_replace_working_configuration() {
    let dir = Directory::new();
    for edit in [0, 1, 2] {
        fs::write(
            dir.paths.resolve("config/server.json").unwrap(),
            b"working-configuration",
        )
        .unwrap();
        let mut files = entries();
        let mut security: serde_json::Value = serde_json::from_slice(&files[1].1).unwrap();
        match edit {
            0 => security["zero_rtt"] = true.into(),
            1 => security["private_key_file"] = "../outside-key.pem".into(),
            _ => files[4].1 = include_bytes!("fixtures/test-server-key.pem").to_vec(),
        }
        files[1].1 = serde_json::to_vec(&security).unwrap();
        let result =
            ClientBundle::from_bytes(archive(files)).and_then(|bundle| bundle.install(&dir.paths));
        assert!(result.is_err());
        assert_eq!(
            fs::read(dir.paths.resolve("config/server.json").unwrap()).unwrap(),
            b"working-configuration"
        );
    }
}

#[test]
fn running_writer_prevents_import() {
    let dir = Directory::new();
    let _lock = dir.paths.lock().unwrap();
    let bundle = ClientBundle::from_bytes(archive(entries())).unwrap();
    assert!(bundle.install(&dir.paths).is_err());
}

#[test]
fn clearing_server_removes_managed_credentials_and_old_backups_but_keeps_rules() {
    let dir = Directory::new();
    let bundle = ClientBundle::from_bytes(archive(entries())).unwrap();
    bundle.install(&dir.paths).unwrap();
    fs::write(dir.paths.resolve("config/rules.json").unwrap(), b"[]").unwrap();
    fs::write(
        dir.paths.resolve("runtime/fakeip_cache.json").unwrap(),
        b"cache",
    )
    .unwrap();
    fs::create_dir_all(dir.paths.resolve("runtime/backups/config-123-456").unwrap()).unwrap();
    for index in 0..5 {
        fs::write(
            dir.paths
                .resolve(format!("runtime/backups/config-123-456/{index}.backup"))
                .unwrap(),
            b"old-secret",
        )
        .unwrap();
    }
    fs::write(
        dir.paths.resolve("runtime/backups/unrelated.txt").unwrap(),
        b"keep",
    )
    .unwrap();
    mtp_splitter::client_bundle::clear_server(&dir.paths).unwrap();
    for file in [
        "config/server.json",
        "config/security.json",
        "config/imported/client-key.pem",
        "config/imported/client.pem",
        "config/imported/gateway-ca.pem",
    ] {
        assert!(!dir.paths.resolve(file).unwrap().exists());
    }
    assert!(
        !dir.paths
            .resolve("runtime/backups/config-123-456")
            .unwrap()
            .exists()
    );
    assert_eq!(
        fs::read(dir.paths.resolve("config/rules.json").unwrap()).unwrap(),
        b"[]"
    );
    assert_eq!(
        fs::read(dir.paths.resolve("runtime/fakeip_cache.json").unwrap()).unwrap(),
        b"cache"
    );
    assert_eq!(
        fs::read(dir.paths.resolve("runtime/backups/unrelated.txt").unwrap()).unwrap(),
        b"keep"
    );
    mtp_splitter::client_bundle::clear_server(&dir.paths).unwrap();
}

#[test]
fn running_writer_prevents_server_deletion() {
    let dir = Directory::new();
    let bundle = ClientBundle::from_bytes(archive(entries())).unwrap();
    bundle.install(&dir.paths).unwrap();
    let _lock = dir.paths.lock().unwrap();
    assert!(mtp_splitter::client_bundle::clear_server(&dir.paths).is_err());
    assert!(dir.paths.resolve("config/server.json").unwrap().is_file());
    assert!(
        dir.paths
            .resolve("config/imported/client-key.pem")
            .unwrap()
            .is_file()
    );
}

#[test]
fn failed_final_write_restores_previous_configuration_without_creating_disk_backup() {
    let dir = Directory::new();
    ClientBundle::from_bytes(archive(entries()))
        .unwrap()
        .install(&dir.paths)
        .unwrap();
    let names = [
        "config/server.json",
        "config/security.json",
        "config/imported/client-key.pem",
        "config/imported/client.pem",
        "config/imported/gateway-ca.pem",
    ];
    let before: Vec<_> = names
        .iter()
        .map(|name| fs::read(dir.paths.resolve(name).unwrap()).unwrap())
        .collect();
    let collision = format!("config/server.tmp-{}", std::process::id());
    fs::write(dir.paths.resolve(&collision).unwrap(), b"occupied").unwrap();
    let mut files = entries();
    let mut server: serde_json::Value = serde_json::from_slice(&files[0].1).unwrap();
    server["port"] = 4443.into();
    files[0].1 = serde_json::to_vec(&server).unwrap();
    let result = ClientBundle::from_bytes(archive(files))
        .unwrap()
        .install(&dir.paths);
    assert!(result.is_err());
    for (name, expected) in names.iter().zip(before) {
        assert_eq!(
            fs::read(dir.paths.resolve(name).unwrap()).unwrap(),
            expected
        );
    }
    assert!(!dir.paths.resolve("runtime/backups").unwrap().exists());
}
