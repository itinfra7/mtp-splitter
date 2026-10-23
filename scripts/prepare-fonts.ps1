# 공개 한국어 글꼴을 고정 해시로 검사하고 앱 내부에만 배치한다.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$FontRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$FontPrefix = $FontRoot.TrimEnd('\') + '\'
function Resolve-FontPath([string]$Relative) {
    $FontResolved = [IO.Path]::GetFullPath((Join-Path $FontRoot $Relative))
    if (-not $FontResolved.StartsWith($FontPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw '글꼴 경로가 앱 밖입니다.' }
    $FontAncestor = $FontResolved
    while ($FontAncestor -and $FontAncestor -ne $FontRoot) {
        if ((Test-Path -LiteralPath $FontAncestor) -and ((Get-Item -LiteralPath $FontAncestor).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw '글꼴 경로가 링크 또는 정션입니다.' }
        $FontAncestor = Split-Path -Parent $FontAncestor
    }
    return $FontResolved
}
foreach ($FontDirectory in @('bin', 'bin\fonts')) {
    $FontDirectoryPath = Resolve-FontPath $FontDirectory
    if (-not (Test-Path -LiteralPath $FontDirectoryPath)) { New-Item -ItemType Directory -Path $FontDirectoryPath | Out-Null }
}
$FontFiles = @(
    @{ Name = 'NanumGothic.ttf'; Remote = 'NanumGothic-Regular.ttf'; Hash = '76f45ef4a6bcff344c837c95a7dcc26e017e38b5846d5ae0cdcb5b86be2e2d31' },
    @{ Name = 'OFL.txt'; Remote = 'OFL.txt'; Hash = 'eeacf16032901d0ed0456876ec77b8f0fda6b3fecec7d972f8543eb602e6c30f' }
)
foreach ($FontFile in $FontFiles) {
    $FontTarget = Resolve-FontPath ('bin\fonts\' + $FontFile.Name)
    if (Test-Path -LiteralPath $FontTarget) {
        if ((Get-FileHash -LiteralPath $FontTarget -Algorithm SHA256).Hash -ieq $FontFile.Hash) { continue }
        throw '기존 글꼴 또는 라이선스의 해시가 다릅니다.'
    }
    $FontTemporary = Resolve-FontPath ('bin\fonts\' + $FontFile.Name + '.download')
    if (Test-Path -LiteralPath $FontTemporary) { throw '이전 다운로드 파일을 확인하십시오.' }
    try {
        Invoke-WebRequest -UseBasicParsing -Uri ('https://raw.githubusercontent.com/google/fonts/main/ofl/nanumgothic/' + $FontFile.Remote) -OutFile $FontTemporary
        if ((Get-FileHash -LiteralPath $FontTemporary -Algorithm SHA256).Hash -ine $FontFile.Hash) { throw '다운로드한 글꼴의 해시가 다릅니다.' }
        Move-Item -LiteralPath $FontTemporary -Destination $FontTarget
    } finally {
        if (Test-Path -LiteralPath $FontTemporary) { Remove-Item -LiteralPath $FontTemporary }
    }
}
Write-Output '앱 내부 글꼴과 라이선스를 확인했습니다.'
