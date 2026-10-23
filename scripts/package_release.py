"""허용한 실행 파일만 묶고 운영 설정·개인키·개발 캐시의 포함을 거부한다."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import struct
import tomllib
import uuid
import zipfile
from public_source import collect


ROOT = Path(__file__).resolve().parent.parent


def checked(relative: str) -> Path:
    """파일과 상위 폴더의 링크를 거부하고 앱 루트 내부인지 검사한다."""
    path = ROOT / relative
    if not path.resolve().is_relative_to(ROOT):
        raise ValueError("배포 입력 또는 출력이 앱 루트 밖입니다")
    for part in [path, *path.parents]:
        if part == ROOT:
            break
        if part.is_symlink() or part.is_junction():
            raise ValueError("배포 경로에 링크 또는 정션이 있습니다")
    return path


def imports(data: bytes) -> list[str]:
    """PE 가져오기 표를 읽어 별도 VC 런타임 설치가 필요한 바이너리를 검출한다."""
    if data[:2] != b"MZ":
        raise ValueError("PE 실행 파일이 아닙니다")
    pe = struct.unpack_from("<I", data, 60)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("PE 서명이 잘못됐습니다")
    machine, count = struct.unpack_from("<HH", data, pe + 4)
    if machine != 0x8664:
        raise ValueError("배포 바이너리가 x64가 아닙니다")
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    if struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise ValueError("PE32+ 헤더가 필요합니다")
    rva, _ = struct.unpack_from("<II", data, optional + 120)
    sections = [struct.unpack_from("<IIII", data, optional + optional_size + index * 40 + 8)
                for index in range(count)]

    def offset(value: int) -> int:
        for virtual_size, virtual_address, raw_size, raw_pointer in sections:
            if virtual_address <= value < virtual_address + max(virtual_size, raw_size):
                return raw_pointer + value - virtual_address
        raise ValueError("PE 섹션 범위 오류")

    cursor = offset(rva)
    result = []
    while any(data[cursor:cursor + 20]):
        name = offset(struct.unpack_from("<I", data, cursor + 12)[0])
        result.append(data[name:data.index(0, name)].decode("ascii"))
        cursor += 20
    return result


def main() -> None:
    version = tomllib.loads(checked("Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
    release = "runtime/build/x86_64-pc-windows-msvc/release"
    source_files = {
        "mtp-splitter.exe": f"{release}/mtp-splitter.exe",
        "bin/watchdog.exe": f"{release}/watchdog.exe",
        "bin/WinDivert.dll": "bin/WinDivert.dll",
        "bin/WinDivert64.sys": "bin/WinDivert64.sys",
        "bin/WinDivert-LICENSE.txt": "bin/WinDivert-LICENSE.txt",
        "bin/WinDivert-README.txt": "bin/WinDivert-README.txt",
        "bin/fonts/NanumGothic.ttf": "bin/fonts/NanumGothic.ttf",
        "bin/fonts/OFL.txt": "bin/fonts/OFL.txt",
    }
    files = {name: checked(source).read_bytes() for name, source in source_files.items()}
    files["LICENSE"] = checked("LICENSE").read_bytes()
    files["README.md"] = checked("README.md").read_bytes()
    files["NOTICE"] = checked("NOTICE").read_bytes()
    source_archive = io.BytesIO()
    with zipfile.ZipFile(source_archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as source_zip:
        for name, data in collect(ROOT).items():
            source_zip.writestr(f"mtp-splitter/{name}", data)
    files["source/mtp-splitter-source.zip"] = source_archive.getvalue()
    expected = {
        "bin/WinDivert.dll": "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2",
        "bin/WinDivert64.sys": "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2",
        "bin/fonts/NanumGothic.ttf": "76f45ef4a6bcff344c837c95a7dcc26e017e38b5846d5ae0cdcb5b86be2e2d31",
    }
    for name, digest in expected.items():
        if hashlib.sha256(files[name]).hexdigest() != digest:
            raise ValueError("드라이버 또는 글꼴의 고정 해시가 다릅니다")
    binary_imports = {}
    for name in ["mtp-splitter.exe", "bin/watchdog.exe", "bin/WinDivert.dll"]:
        binary_imports[name] = imports(files[name])
        if any(dll.lower().startswith(("vcruntime", "msvcp", "api-ms-win-crt")) or dll.lower() == "ucrtbase.dll"
               for dll in binary_imports[name]):
            raise ValueError("별도 VC 런타임을 요구합니다. 정적 CRT 배포 빌드를 사용하십시오")

    files["config/rules.json"] = b"[]\n"
    guide = f"""mtp-splitter {version} / Windows x64

실행
1. ZIP 전체를 한 폴더에 압축 해제합니다.
2. mtp-splitter.exe를 우클릭하고 관리자 권한으로 실행합니다.
3. 첫 화면의 ZIP 불러오기에서 서버가 발급한 설정 ZIP을 선택합니다.
4. 앱 추가로 EXE를 선택하고 저장한 뒤 연결 시작을 누릅니다.

설정 ZIP을 수동으로 풀 필요가 없습니다. 창으로 끌어 놓아도 가져옵니다.
설정을 바꾸려면 종료 · 차단 해제를 누르십시오.
중지 · 차단 유지는 터널을 끊고 대상 앱의 직접 연결 차단을 유지합니다.
종료 · 차단 해제는 대상 앱의 일반 인터넷 연결을 허용합니다.
서버 탭의 서버 설정 삭제로 구성과 인증서를 지울 수 있습니다.

이 배포본에는 서버 주소, 운영 비밀값, 인증서, 개인키가 없습니다.
서버 발급 ZIP과 가져온 config 폴더를 다른 사람에게 공유하지 마십시오.
실행 파일·드라이버·설정·캐시·로그는 압축 해제한 폴더 안에 둡니다.
별도 설치 프로그램과 VC 런타임 설치가 필요하지 않은 정적 CRT 빌드입니다.
일반 Telegram MTProxy는 임의 앱의 TCP·UDP 중계 서버로 쓸 수 없습니다.
연결 단절·메인 종료 뒤에는 watchdog이 차단합니다. 두 프로세스를 모두 종료하거나
재부팅한 뒤의 차단, Windows DNS 대리 전송의 완전한 앱 귀속은 보장하지 않습니다.

WinDivert 2.2.2 원본: https://github.com/basil00/WinDivert/releases/tag/v2.2.2
드라이버 라이선스와 한국어 글꼴 라이선스는 bin의 해당 파일을 참고하십시오.
"""
    files["사용방법.txt"] = guide.replace("\n", "\r\n").encode("utf-8-sig")

    # Cargo 캐시의 공개 라이선스만 복사하며 crate 소스와 테스트 키는 넣지 않는다.
    locked = tomllib.loads(checked("Cargo.lock").read_text(encoding="utf-8"))
    notices = []
    registry = checked("runtime/cargo-home/registry/src")
    for package in locked["package"]:
        if not package.get("source", "").startswith("registry+"):
            continue
        name, crate_version = package["name"], package["version"]
        candidates = list(registry.glob(f"*/{name}-{crate_version}/Cargo.toml"))
        if len(candidates) != 1:
            continue
        manifest_path = checked(str(candidates[0].relative_to(ROOT)))
        metadata = tomllib.loads(manifest_path.read_text(encoding="utf-8"))["package"]
        notices.append(f"{name} {crate_version}: {metadata.get('license', '개별 파일 참고')}")
        for license_path in manifest_path.parent.iterdir():
            if license_path.is_file() and license_path.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT")):
                license_path = checked(str(license_path.relative_to(ROOT)))
                files[f"licenses/{name}-{crate_version}/{license_path.name}"] = license_path.read_bytes()
    files["licenses/THIRD-PARTY-NOTICES.txt"] = ("\n".join(notices) + "\n").encode("utf-8")
    manifest = {
        "version": version,
        "target": "x86_64-pc-windows-msvc",
        "crt_static": True,
        "private_configuration_included": False,
        "imports": binary_imports,
        "files": {name: {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                  for name, data in sorted(files.items())},
    }
    files["manifest.json"] = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
    output = checked("dist")
    output.mkdir(exist_ok=True)
    archive = checked(f"dist/mtp-splitter-v{version}-windows-x86_64.zip")
    source_output = checked(f"dist/mtp-splitter-v{version}-source.zip")
    source_output.write_bytes(source_archive.getvalue())
    temporary = checked(f"dist/.package-{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
                for directory in ["runtime/", "logs/"]:
                    bundle.writestr(f"mtp-splitter/{directory}", b"")
                for name, data in sorted(files.items()):
                    bundle.writestr(f"mtp-splitter/{name}", data)
        with zipfile.ZipFile(temporary) as bundle:
            if bundle.testzip() is not None:
                raise ValueError("배포 ZIP의 CRC 검사 실패")
            if any(name.endswith((".pem", ".key", ".pfx")) for name in bundle.namelist()):
                raise ValueError("배포 ZIP에 인증서 또는 개인키가 있습니다")
        os.replace(temporary, archive)
    finally:
        temporary.unlink(missing_ok=True)
    # 공개한 두 압축 파일의 이름과 해시를 같은 형식으로 기록한다.
    checksums = "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                        for path in [archive, source_output])
    checked("dist/SHA256SUMS").write_text(checksums, encoding="utf-8", newline="\n")
    print(f"배포 ZIP 생성: {archive.name} ({archive.stat().st_size:,}바이트)")


if __name__ == "__main__":
    main()
