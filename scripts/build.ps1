# 모든 빌드 출력과 Cargo 캐시를 앱 내부에 고정하고 배포 경로로 복사한다.
[CmdletBinding()]
param([switch]$SkipTests)

$ErrorActionPreference = 'Stop'
$TaskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$TaskPrefix = $TaskRoot.TrimEnd('\') + '\'
foreach ($TaskName in @('bin', 'runtime', 'runtime\tmp', 'runtime\cargo-home', 'logs')) {
    $TaskPath = [IO.Path]::GetFullPath((Join-Path $TaskRoot $TaskName))
    if (-not $TaskPath.StartsWith($TaskPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw '출력 경로가 앱 루트 밖입니다.' }
    if (Test-Path -LiteralPath $TaskPath) {
        if ((Get-Item -LiteralPath $TaskPath).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "출력 폴더가 정션 또는 링크입니다: $TaskPath" }
    } else { New-Item -ItemType Directory -Path $TaskPath | Out-Null }
}

$TaskOldLocation = Get-Location
$TaskSavedEnvironment = @{}
foreach ($TaskVariable in @('CARGO_HOME', 'TMP', 'TEMP')) { $TaskSavedEnvironment[$TaskVariable] = [Environment]::GetEnvironmentVariable($TaskVariable, 'Process') }

function Invoke-TaskCargo([string[]]$CargoArguments) {
    & cargo @CargoArguments
    if ($LASTEXITCODE -ne 0) { throw "Cargo 실행 실패: $($CargoArguments -join ' ')" }
}

try {
    Set-Location -LiteralPath $TaskRoot
    $env:CARGO_HOME = Join-Path $TaskRoot 'runtime\cargo-home'
    $env:TMP = Join-Path $TaskRoot 'runtime\tmp'
    $env:TEMP = $env:TMP
    Invoke-TaskCargo -CargoArguments @('fmt', '--all', '--check')
    Invoke-TaskCargo -CargoArguments @('check', '--workspace', '--all-targets', '--locked')
    Invoke-TaskCargo -CargoArguments @('clippy', '--workspace', '--all-targets', '--locked', '--', '-D', 'warnings')
    if (-not $SkipTests) { Invoke-TaskCargo -CargoArguments @('test', '--workspace', '--locked') }
    Invoke-TaskCargo -CargoArguments @('build', '--workspace', '--release', '--locked', '--target', 'x86_64-pc-windows-msvc', '--config', 'target.x86_64-pc-windows-msvc.rustflags=["-C","target-feature=+crt-static"]')
    Copy-Item -LiteralPath (Join-Path $TaskRoot 'runtime\build\x86_64-pc-windows-msvc\release\mtp-splitter.exe') -Destination (Join-Path $TaskRoot 'mtp-splitter.exe') -Force
    Copy-Item -LiteralPath (Join-Path $TaskRoot 'runtime\build\x86_64-pc-windows-msvc\release\watchdog.exe') -Destination (Join-Path $TaskRoot 'bin\watchdog.exe') -Force
    Write-Output '검증한 실행 파일을 앱 루트와 bin에 배치했습니다. 드라이버를 설치하거나 실행하지 않았습니다.'
} finally {
    foreach ($TaskVariable in $TaskSavedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($TaskVariable, $TaskSavedEnvironment[$TaskVariable], 'Process') }
    Set-Location -LiteralPath $TaskOldLocation
}
