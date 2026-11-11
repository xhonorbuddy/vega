<#
    Builds the scratch artifacts used by run_tests.ps1:
      target.exe   - a long-running process to map into
      sample.dll   - payload that exercises TLS, exceptions, delay imports
      minimal.dll  - payload with no CRT features (isolates loader bugs)

    Usage: powershell -ExecutionPolicy Bypass -File tests\build_artifacts.ps1
#>

param(
    [string] $Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'

$work = Join-Path $env:TEMP 'vega-tests'

function Import-VcEnvironment {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"

    if (-not (Test-Path $vswhere)) {
        throw "vswhere.exe not found; install Visual Studio C++ tools"
    }

    $installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath

    if (-not $installation) {
        throw "No Visual Studio C++ toolset found"
    }

    $vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvars64.bat'

    if (-not (Test-Path $vcvars)) {
        throw "vcvars64.bat not found under $installation"
    }

    $cmdExe = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $batch = Join-Path $env:TEMP 'vega_vcvars.cmd'

    @"
@echo off
call "$vcvars" >nul 2>&1
set
"@ | Set-Content -Path $batch -Encoding Ascii

    try {
        $dump = & $cmdExe /c $batch
    }
    finally {
        Remove-Item $batch -ErrorAction SilentlyContinue
    }

    foreach ($line in $dump) {
        if ($line -match '^([^=]+)=(.*)$') {
            try {
                Set-Item -Path "env:$($matches[1])" -Value $matches[2] -ErrorAction Stop
            }
            catch {
                # Some shell-managed variables are read-only; ignore them.
            }
        }
    }

    # vcvars sometimes fails to locate the Windows SDK (for example when the
    # registry is restricted). Add it from disk so cl.exe can find windows.h.
    if ($env:INCLUDE -notmatch 'Windows Kits') {
        $sdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
        $sdkVersion = Get-ChildItem (Join-Path $sdkRoot 'Include') -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending |
            Select-Object -First 1

        if (-not $sdkVersion) {
            throw "Windows SDK not found under $sdkRoot"
        }

        $sdkInclude = $sdkVersion.FullName
        $sdkLib = Join-Path $sdkRoot "Lib\$($sdkVersion.Name)"

        $env:INCLUDE = "$sdkInclude\ucrt;$sdkInclude\um;$sdkInclude\shared;$env:INCLUDE"
        $env:LIB = "$sdkLib\ucrt\x64;$sdkLib\um\x64;$env:LIB"
    }
}

Write-Host "== Building test artifacts in $work =="

New-Item -ItemType Directory -Force -Path $work | Out-Null
Import-VcEnvironment

Push-Location $work

try {
    & cl.exe /nologo /EHsc /MT /O2 /DNDEBUG "/Fe:$work\target.exe" "/Fo:$work\target.obj" "$Root\tests\target\target.cpp" /link /SUBSYSTEM:CONSOLE user32.lib
    if ($LASTEXITCODE -ne 0) {
        throw "failed to build target.exe"
    }

    # /BASE collides with the target image on purpose so the mapper must relocate.
    & cl.exe /nologo /EHsc /MT /O2 /DNDEBUG /LD "/Fe:$work\sample.dll" "/Fo:$work\sample.obj" "$Root\tests\sample\sample.cpp" /link /BASE:0x140000000 /DELAYLOAD:user32.dll user32.lib delayimp.lib
    if ($LASTEXITCODE -ne 0) {
        throw "failed to build sample.dll"
    }

    & cl.exe /nologo /EHsc /MT /O2 /DNDEBUG /LD "/Fe:$work\minimal.dll" "/Fo:$work\minimal.obj" "$Root\tests\minimal\minimal.cpp" /link /BASE:0x150000000
    if ($LASTEXITCODE -ne 0) {
        throw "failed to build minimal.dll"
    }

    & cl.exe /nologo /EHsc /MT /O2 /DNDEBUG /LD "/Fe:$work\blocking.dll" "/Fo:$work\blocking.obj" "$Root\tests\blocking\blocking.cpp" /link /BASE:0x160000000
    if ($LASTEXITCODE -ne 0) {
        throw "failed to build blocking.dll"
    }
}
finally {
    Pop-Location
}

Write-Host "== Artifacts ready =="
