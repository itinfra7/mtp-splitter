# mtp-splitter

Windows GUI client for per-application TCP, UDP and DNS tunneling.

Server: [mtp-gateway](https://github.com/itinfra7/mtp-gateway).

Author: **itinfra7 from GitHub**  
License: **AGPL-3.0-only**; third-party notices are in [NOTICE](NOTICE).

The transport uses Fake-TLS ee, Obfuscated2, explicit padded chunks, TLS 1.3 mutual authentication and multiplexing. UDP uses UDP-over-TCP.

## Build

Windows x86_64, Rust 1.88 or later, the x64 MSVC toolchain and Windows SDK.

```powershell
.\scripts\prepare-fonts.ps1
.\scripts\build.ps1
```

## Install

Download the Windows archive from [Releases](https://github.com/itinfra7/mtp-splitter/releases), verify `SHA256SUMS` and extract it. DirectX 12 and administrator privileges are required. Release archives include WinDivert; for source builds, place `WinDivert.dll` and the signed `WinDivert64.sys` from the [WinDivert 2.2.2 release](https://github.com/basil00/WinDivert/releases/tag/v2.2.2) in `bin/`.

```powershell
.\mtp-splitter.exe
```

Run as administrator, import the gateway configuration ZIP, add applications and connect. Stop disconnects the tunnel and keeps applications blocked; Release terminates the tunnel and watchdog, allowing direct connections. Stop and release before importing or deleting server settings. The Server tab can delete server settings while preserving application rules.

## Manage

```powershell
.\mtp-splitter.exe import-client .\client-desktop.zip
.\mtp-splitter.exe doctor
.\mtp-splitter.exe gateway-probe
.\mtp-splitter.exe processes
.\mtp-splitter.exe clear-server
```

Keep exported credentials private. [Server deployment](https://github.com/itinfra7/mtp-gateway/blob/main/docs/DEPLOYMENT.ko.md), [protocol](https://github.com/itinfra7/mtp-gateway/blob/main/docs/PROTOCOL.ko.md), [client integration](https://github.com/itinfra7/mtp-gateway/blob/main/docs/CLIENT_INTEGRATION.ko.md).
