"""공개 저장소와 소스 배포에 필요한 클라이언트 파일만 선택한다."""

from pathlib import Path


def collect(root: Path) -> dict[str, bytes]:
    root = root.resolve()
    selected = [
        "Cargo.toml", "Cargo.lock", "README.md", "LICENSE", "NOTICE", ".gitignore", ".cargo/config.toml",
        "watchdog/Cargo.toml",
        "examples/config/server.json", "examples/config/security.json", "examples/config/rules.json",
        "scripts/build.ps1", "scripts/prepare-fonts.ps1", "scripts/prepare-windivert.ps1",
        "scripts/package_release.py", "scripts/public_source.py",
        "bin/WinDivert-LICENSE.txt", "bin/WinDivert-README.txt", "bin/fonts/OFL.txt",
    ]
    for directory in ["src", "watchdog/src", "tests"]:
        selected.extend(path.relative_to(root).as_posix() for path in sorted((root / directory).rglob("*.rs")))
    # 테스트 인증서는 공개 고정값만 포함한다. 운영 PEM을 패턴으로 수집하지 않는다.
    for name in ["test-ca.pem", "test-client.pem", "test-client-key.pem", "test-server.pem", "test-server-key.pem", "packets.json", "obfuscated.json", "fake_tls.json"]:
        selected.append(f"tests/fixtures/{name}")
    result = {}
    for relative in sorted(set(selected)):
        path = root / relative
        if not path.resolve().is_relative_to(root):
            raise ValueError("공개 소스가 프로젝트 밖을 가리킵니다")
        for parent in [path, *path.parents]:
            if parent == root:
                break
            if parent.is_symlink() or parent.is_junction():
                raise ValueError("공개 소스에 링크 또는 정션이 있습니다")
        result[relative] = path.read_bytes()
    return result
