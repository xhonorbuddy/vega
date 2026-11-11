<#
    Diagnostic: sweeps the fabricated Ddag node's state field and reports which
    value makes the loader's address/name lookups see the mapped image.

    Usage: powershell -ExecutionPolicy Bypass -File tests\probe_ddag.ps1
#>

param(
    [string] $Root = (Split-Path -Parent $PSScriptRoot),
    [int] $From = 0,
    [int] $To = 9
)

$ErrorActionPreference = 'Stop'

$work = Join-Path $Root 'x64\Test'
$vega = Join-Path $Root 'vega\x64\Release\vega.exe'
$log = Join-Path $work 'sample.log'

if (-not (Test-Path (Join-Path $work 'target.exe'))) {
    throw "test artifacts missing; run tests\build_artifacts.ps1 first"
}

Stop-Process -Name target -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300

for ($state = $From; $state -le $To; ++$state) {
    Stop-Process -Name target -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 250
    Remove-Item $log -ErrorAction SilentlyContinue

    $env:VEGA_TEST_LOG = $log

    $target = Start-Process -FilePath (Join-Path $work 'target.exe') -WorkingDirectory $work -PassThru
    Start-Sleep -Milliseconds 700

    $output = & $vega --process target.exe --dll (Join-Path $work 'sample.dll') --no-preferred --loader-entry --ddag-state $state 2>&1
    $exit = $LASTEXITCODE
    Start-Sleep -Milliseconds 250

    $lines = @()
    if (Test-Path $log) {
        $lines = Get-Content $log
    }

    $byAddress = ($lines -match 'getmodule:') -join ' '
    $byName = ($lines | Where-Object { $_ -match '^pctofileheader:' }) -join ' '
    $survived = -not $target.HasExited

    Write-Host ("state={0,-2} exit={1} alive={2,-5} {3} {4}" -f $state, $exit, $survived, $byAddress, $byName)

    if (-not $target.HasExited) {
        Stop-Process -Id $target.Id -Force -ErrorAction SilentlyContinue
    }
}

Stop-Process -Name target -Force -ErrorAction SilentlyContinue
Remove-Item Env:\VEGA_TEST_LOG -ErrorAction SilentlyContinue
