<#
.SYNOPSIS
    Fetches ms-tpm-20-ref + SymCrypt and builds ftpmsim.sys (ARM64, KMDF 1.15) with the EWDK 10.0.18362.

.EXAMPLE
    .\Build-FtpmSim.ps1 -Ewdk E:\ -WorkRoot C:\temp\ftpmsim

    -WorkRoot receives the third-party checkouts (<WorkRoot>\ThirdParty) and all build output
    (<WorkRoot>\out, <WorkRoot>\obj), so the source tree stays clean. Without -WorkRoot the
    checkouts go to .\ThirdParty (git-ignored) and the output to .\build.
#>
param(
    [string]$Ewdk = 'E:\',
    [string]$WorkRoot = '',
    [ValidateSet('Release', 'Debug')][string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$proj = Join-Path $PSScriptRoot 'ftpmsim.vcxproj'

$tp = if ($WorkRoot) { Join-Path $WorkRoot 'ThirdParty' } else { Join-Path $PSScriptRoot 'ThirdParty' }
if (-not (Test-Path (Join-Path $tp 'ms-tpm-20-ref\TPMCmd')) -or -not (Test-Path (Join-Path $tp 'SymCrypt\lib'))) {
    & (Join-Path $PSScriptRoot 'ThirdParty\fetch.ps1') -Root $tp
}

$props = "/p:Platform=ARM64 /p:Configuration=$Configuration /p:ThirdPartyRoot=`"$tp`""
if ($WorkRoot) {
    # a trailing backslash must be doubled inside the quotes (CommandLineToArgvW rules)
    $props += " /p:OutDir=`"$WorkRoot\out\\`" /p:IntDir=`"$WorkRoot\obj\\`""
}

# The ARM64 cross compiler (x64 host tools) and MSBuild come from the EWDK environment. Compiler,
# linker and msbuild must run in the same cmd.exe process as the environment script.
$setup = Join-Path $Ewdk 'BuildEnv\SetupBuildEnv.cmd'
cmd /c "call `"$setup`" amd64 >nul 2>&1 && msbuild `"$proj`" $props /nologo /v:m /m"
if ($LASTEXITCODE -ne 0) { throw "msbuild failed ($LASTEXITCODE)" }
