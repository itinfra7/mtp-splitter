# 복원된 공식 x64 배포물을 앱 내부에서 검사하고 배치한다. 드라이버를 로드하지 않는다.
[CmdletBinding()]
param([string]$Archive = 'runtime\downloads\WinDivert-2.2.2-A.zip')

$ErrorActionPreference = 'Stop'
$TaskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$TaskPrefix = $TaskRoot.TrimEnd('\') + '\'

function Resolve-TaskPath([string]$RelativePath) {
    if ([IO.Path]::IsPathRooted($RelativePath)) { throw '앱 안의 상대 경로만 허용합니다.' }
    $TaskResolved = [IO.Path]::GetFullPath((Join-Path $TaskRoot $RelativePath))
    if (-not $TaskResolved.StartsWith($TaskPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw '경로가 앱 루트 밖입니다.' }
    $TaskAncestor = $TaskResolved
    while ($TaskAncestor -and $TaskAncestor.StartsWith($TaskRoot, [StringComparison]::OrdinalIgnoreCase)) {
        if (Test-Path -LiteralPath $TaskAncestor) {
            if ((Get-Item -LiteralPath $TaskAncestor).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "정션 또는 링크는 허용하지 않습니다: $TaskAncestor" }
        }
        if ($TaskAncestor -eq $TaskRoot) { break }
        $TaskAncestor = Split-Path -Parent $TaskAncestor
    }
    return $TaskResolved
}

# 해시는 이 프로젝트에서 직접 받은 공식 2.2.2-A ZIP을 고정한다. 배포자가 별도로 공표한 해시라는 뜻은 아니다.
$TaskArchivePath = Resolve-TaskPath $Archive
$TaskArchiveHash = (Get-FileHash -LiteralPath $TaskArchivePath -Algorithm SHA256).Hash
if ($TaskArchiveHash -ne '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15') {
    throw '고정한 WinDivert 2.2.2-A 아카이브와 SHA-256이 다릅니다. 새 버전은 출처와 서명을 다시 검증해야 합니다.'
}

foreach ($TaskDirectory in @('bin', 'runtime', 'runtime\tmp', 'runtime\verification')) {
    $TaskDirectoryPath = Resolve-TaskPath $TaskDirectory
    if (-not (Test-Path -LiteralPath $TaskDirectoryPath)) { New-Item -ItemType Directory -Path $TaskDirectoryPath | Out-Null }
}
$TaskStage = Resolve-TaskPath ('runtime\tmp\windivert-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TaskStage | Out-Null

$TaskEntries = @(
    @{ Source = 'WinDivert-2.2.2-A/x64/WinDivert.dll'; Name = 'WinDivert.dll'; Hash = 'C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2' },
    @{ Source = 'WinDivert-2.2.2-A/x64/WinDivert64.sys'; Name = 'WinDivert64.sys'; Hash = '8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2' },
    @{ Source = 'WinDivert-2.2.2-A/LICENSE'; Name = 'WinDivert-LICENSE.txt'; Hash = '14A0CB5214D536E4FDAE6AA3F5696F981EEDA106CD026E9794BBA489EE79D628' },
    @{ Source = 'WinDivert-2.2.2-A/README'; Name = 'WinDivert-README.txt'; Hash = '6A208EFAC504974E1BDFE075584FA1DC49DB0A4D18CA1CEAA2D45E65934A02E4' }
)

Add-Type -AssemblyName System.IO.Compression.FileSystem
$TaskZip = [IO.Compression.ZipFile]::OpenRead($TaskArchivePath)
try {
    foreach ($TaskEntry in $TaskEntries) {
        $TaskMember = $TaskZip.GetEntry($TaskEntry.Source)
        if (-not $TaskMember -or $TaskMember.Length -le 0 -or $TaskMember.Length -gt 1048576) { throw "압축 항목이 없거나 크기가 잘못됐습니다: $($TaskEntry.Source)" }
        $TaskDestination = Join-Path $TaskStage $TaskEntry.Name
        [IO.Compression.ZipFileExtensions]::ExtractToFile($TaskMember, $TaskDestination, $false)
        if ((Get-FileHash -LiteralPath $TaskDestination -Algorithm SHA256).Hash -ne $TaskEntry.Hash) { throw "압축 항목의 해시가 다릅니다: $($TaskEntry.Name)" }
    }
} finally { $TaskZip.Dispose() }

$TaskDriverSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $TaskStage 'WinDivert64.sys')
if ($TaskDriverSignature.Status -ne 'Valid') { throw "커널 드라이버 서명 검증 실패: $($TaskDriverSignature.StatusMessage)" }
$TaskDllSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $TaskStage 'WinDivert.dll')
$TaskEvidence = @()
foreach ($TaskEntry in $TaskEntries) {
    $TaskDestination = Resolve-TaskPath ('bin\' + $TaskEntry.Name)
    Copy-Item -LiteralPath (Join-Path $TaskStage $TaskEntry.Name) -Destination $TaskDestination -Force
    $TaskPlacedHash = (Get-FileHash -LiteralPath $TaskDestination -Algorithm SHA256).Hash
    if ($TaskPlacedHash -ne $TaskEntry.Hash) { throw "배치한 파일의 해시가 다릅니다: $($TaskEntry.Name)" }
    $TaskEvidence += [ordered]@{ path = 'bin/' + $TaskEntry.Name; sha256 = $TaskPlacedHash }
}
$TaskRecord = [ordered]@{
    archive = $Archive
    archive_sha256 = $TaskArchiveHash
    checked_at = [DateTime]::UtcNow.ToString('o')
    driver_signature = [string]$TaskDriverSignature.Status
    driver_signer = $TaskDriverSignature.SignerCertificate.Subject
    driver_signer_thumbprint = $TaskDriverSignature.SignerCertificate.Thumbprint
    dll_signature = [string]$TaskDllSignature.Status
    files = $TaskEvidence
}
[IO.File]::WriteAllText((Resolve-TaskPath 'runtime\verification\driver-installed.json'), ($TaskRecord | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))

# 삭제 대상은 앞에서 확인한 앱 내부 임시 폴더의 고정 파일뿐이다. 재귀 삭제를 사용하지 않는다.
foreach ($TaskEntry in $TaskEntries) { Remove-Item -LiteralPath (Join-Path $TaskStage $TaskEntry.Name) }
Remove-Item -LiteralPath $TaskStage
Write-Output 'x64 DLL·서명 검증된 SYS·라이선스를 bin에 배치했습니다. 드라이버는 로드하지 않았습니다.'
