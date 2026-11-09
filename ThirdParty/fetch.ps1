<#
.SYNOPSIS
    Fetches the two open-source components ftpmsim.sys is built from.

.DESCRIPTION
    Clones the revisions that reproduce the shipped binary (PE timestamp 2019-04-13):

      ms-tpm-20-ref  ee21db0a941decd3cac67925ea3310873af60ab3  (2018-10-29, the last revision
                     before rev. 1.52; the structure sizes of the binary - OBJECT 0x718, gp 0x318,
                     gr 0x138, gc 0x6ec - only come out with this generation of the code)
      SymCrypt       286762b7730e2b780678f5ab11fef2b1bad639e0  (2019-04-11, "SymCrypt v87")

    into <Root>\ms-tpm-20-ref and <Root>\SymCrypt and applies
    patches\ms-tpm-20-ref-ftpmsim.patch (library selection: SymCrypt hashes/AES, "MsBn"
    math adapter, curve set). Nothing is committed; the clones are git-ignored.

.PARAMETER Root
    Destination (default: this ThirdParty folder). Pass the same folder as
    /p:ThirdPartyRoot=<Root> to MSBuild.
#>
param(
    [string]$Root = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'

$components = @(
    @{ Name = 'ms-tpm-20-ref'; Url = 'https://github.com/microsoft/ms-tpm-20-ref';
       Commit = 'ee21db0a941decd3cac67925ea3310873af60ab3' },
    @{ Name = 'SymCrypt'; Url = 'https://github.com/microsoft/SymCrypt.git';
       Commit = '286762b7730e2b780678f5ab11fef2b1bad639e0' }
)

New-Item -ItemType Directory -Force $Root | Out-Null

foreach ($c in $components) {
    $dir = Join-Path $Root $c.Name
    if (-not (Test-Path (Join-Path $dir '.git'))) {
        git clone --quiet $c.Url $dir
        if ($LASTEXITCODE -ne 0) { throw "clone of $($c.Url) failed" }
    }
    git -C $dir reset --quiet --hard
    git -C $dir checkout --quiet $c.Commit
    if ($LASTEXITCODE -ne 0) { throw "checkout of $($c.Commit) failed" }
    Write-Host ("{0} @ {1}" -f $c.Name, (git -C $dir rev-parse --short HEAD))
}

$patch = Join-Path $PSScriptRoot 'patches\ms-tpm-20-ref-ftpmsim.patch'
git -C (Join-Path $Root 'ms-tpm-20-ref') apply --whitespace=nowarn $patch
if ($LASTEXITCODE -ne 0) { throw "patch $patch did not apply" }
Write-Host 'patched ms-tpm-20-ref (Implementation.h)'

python3 (Join-Path $Root 'SymCrypt' 'scripts' 'version.py') --build-info
