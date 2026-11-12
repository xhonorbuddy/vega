<#
    One-shot live verification for the Wow_loader detection work.

    Usage:
      # you already have WoW at the login screen / in world
      powershell -ExecutionPolicy Bypass -File vega_live_verify.ps1

      # let the script start the client, then close it afterwards
      powershell -ExecutionPolicy Bypass -File vega_live_verify.ps1 -Launch -CloseAfter

    It injects grid.dll with a copy of vega.exe (executables launched from the
    workspace are restricted in this DSH session), waits, then prints the new
    log lines and any crash report produced during the window.
#>

param(
    [switch] $Launch,
    [int] $WaitSeconds = 240,
    [switch] $CloseAfter
)

$ErrorActionPreference = 'Stop'

$repo = 'C:\Users\DELTA\Documents\GitHub\vega'
$game = 'C:\Program Files (x86)\World of Warcraft\_forever_'
$work = Join-Path $env:TEMP 'vega_live'
$log = Join-Path $env:TEMP 'grid_lua.log'
$errors = Join-Path $game 'Errors'

New-Item -ItemType Directory -Force -Path $work | Out-Null
Copy-Item (Join-Path $repo 'bin\x64\Release\vega.exe') (Join-Path $work 'vega.exe') -Force

function Get-Wow {
    Get-Process -Name Wow -ErrorAction SilentlyContinue | Select-Object -First 1
}

if ($Launch -and -not (Get-Wow)) {
    Write-Host 'starting Wow.exe ...'
    Start-Process -FilePath (Join-Path $game 'Wow.exe') -WorkingDirectory $game
}

$deadline = (Get-Date).AddMinutes(5)

while (-not (Get-Wow) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
}

$wow = Get-Wow

if (-not $wow) {
    Write-Host 'Wow.exe is not running; start the client and rerun.'
    exit 2
}

Write-Host ("Wow pid={0}" -f $wow.Id)

$logBefore = 0
if (Test-Path $log) { $logBefore = (Get-Content $log).Count }

$startedAt = Get-Date

Write-Host 'injecting grid.dll ...'
& (Join-Path $work 'vega.exe') -p Wow.exe -d (Join-Path $repo 'bin\x64\Release\grid.dll') 2>&1 | ForEach-Object { $_ }
Write-Host ("inject exit={0}" -f $LASTEXITCODE)

Write-Host ("waiting {0}s ..." -f $WaitSeconds)
Start-Sleep -Seconds $WaitSeconds

Write-Host '=== new log lines ==='
if (Test-Path $log) {
    Get-Content $log | Select-Object -Skip $logBefore | ForEach-Object { $_ }
}
else {
    Write-Host '(no log file)'
}

Write-Host '=== crash reports during window ==='
Get-ChildItem $errors -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -ge $startedAt } |
    Select-Object Name, LastWriteTime |
    Format-Table -AutoSize | Out-String

$wow = Get-Wow

if ($wow) {
    Write-Host ("Wow still running: {0}, responding: {1}" -f $wow.Id, $wow.Responding)
}
else {
    Write-Host 'Wow exited.'
}

if ($CloseAfter) {
    $wow = Get-Wow

    if ($wow) {
        Stop-Process -Id $wow.Id -Force
        Write-Host 'closed Wow.'
    }
}
