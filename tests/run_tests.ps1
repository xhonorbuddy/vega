<#
    End-to-end test for the Vega manual mapper.

    Builds a scratch target process and payloads, maps a payload into the
    running target, asserts on what the payload reported from inside that
    process, then unloads it and asserts on the detach path.

    Exit code 0 means every assertion passed.
#>

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$work = Join-Path $env:TEMP 'vega-tests'
$log = Join-Path $work 'sample.log'

# The project's output folder is configurable, so probe the usual layouts.
$vega = @(
    (Join-Path $root 'bin\x64\Release\vega.exe'),
    (Join-Path $root 'vega\bin\x64\Release\vega.exe'),
    (Join-Path $root 'vega\x64\Release\vega.exe')
) | Where-Object { Test-Path $_ } | Select-Object -First 1

$failures = New-Object System.Collections.Generic.List[string]

function Assert-True {
    param([bool] $Condition, [string] $Message)

    if ($Condition) {
        Write-Host "  [ok]   $Message"
    }
    else {
        Write-Host "  [FAIL] $Message" -ForegroundColor Red
        $script:failures.Add($Message)
    }
}

function Assert-LogContains {
    param([string[]] $Lines, [string] $Needle, [string] $Message)

    Assert-True -Condition (($Lines -match [regex]::Escape($Needle)).Count -gt 0) -Message $Message
}

Write-Host "== Building artifacts =="
& (Join-Path $PSScriptRoot 'build_artifacts.ps1') -Root $root

if (-not $vega) {
    throw "vega.exe not found under bin\x64\Release or vega\...; build the Release|x64 configuration first"
}

Write-Host "== Preparing target process =="

# Never reuse a stale target left over from an earlier run: the mapper finds
# processes by image name.
Get-Process -Name target -ErrorAction SilentlyContinue | ForEach-Object { $_.Kill() }
Start-Sleep -Milliseconds 400

Remove-Item $log -ErrorAction SilentlyContinue
$env:VEGA_TEST_LOG = $log
$env:VEGA_TEST_THROW = "1"

$target = Start-Process -FilePath (Join-Path $work 'target.exe') -WorkingDirectory $work -PassThru

try {
    Start-Sleep -Milliseconds 800

    Write-Host "== Mapping sample.dll into target.exe =="

    $mapOutput = & $vega --process target.exe --dll (Join-Path $work 'sample.dll') --no-preferred 2>&1
    $mapExit = $LASTEXITCODE
    $mapOutput | ForEach-Object { Write-Host "  $_" }

    Assert-True -Condition ($mapExit -eq 0) -Message "mapper exited with 0 (got $mapExit)"
    Assert-True -Condition (($mapOutput -join "`n") -match 'loader PC index') -Message 'image registered in the loader PC index'

    Start-Sleep -Milliseconds 400

    $logLines = @()
    if (Test-Path $log) {
        $logLines = Get-Content $log
    }

    Assert-LogContains -Lines $logLines -Needle 'tls:attach' -Message 'TLS callback ran (DLL_PROCESS_ATTACH)'
    Assert-LogContains -Lines $logLines -Needle 'dllmain:attach' -Message 'DllMain ran (DLL_PROCESS_ATTACH)'
    Assert-LogContains -Lines $logLines -Needle 'dllmain:delay:' -Message 'delay-loaded import resolved'
    Assert-LogContains -Lines $logLines -Needle 'dllmain:marker:' -Message 'ordinary imports callable'
    Assert-LogContains -Lines $logLines -Needle 'seh:caught' -Message 'SEH handler ran inside the mapped DLL (unwind table registered)'
    Assert-LogContains -Lines $logLines -Needle 'getmodule:byaddress:' -Message 'payload reached its own lookup probes'
    Assert-LogContains -Lines $logLines -Needle 'pctofileheader:found:1' -Message 'RtlPcToFileHeader resolves the mapped image'
    Assert-LogContains -Lines $logLines -Needle 'throw:int:caught:42' -Message 'C++ exception (int) thrown and caught inside the mapped DLL'
    Assert-LogContains -Lines $logLines -Needle 'dllmain:exception:boom' -Message 'C++ exception (std::runtime_error) thrown and caught'

    $order = $logLines | Where-Object { $_ -match '^(tls:attach|dllmain:attach)$' }
    Assert-True -Condition ($order.Count -ge 2 -and $order[0] -eq 'tls:attach') -Message 'TLS callback runs before DllMain'

    Write-Host "== Listing mapped modules =="
    $listOutput = & $vega --process target.exe --list 2>&1
    $listExit = $LASTEXITCODE
    $listOutput | ForEach-Object { Write-Host "  $_" }
    Assert-True -Condition ($listExit -eq 0 -and ($listOutput -join "`n") -match 'sample\.dll') -Message 'module record is discoverable'

    Write-Host "== Unloading sample.dll =="
    $unloadOutput = & $vega --process target.exe --unload --module sample.dll 2>&1
    $unloadExit = $LASTEXITCODE
    $unloadOutput | ForEach-Object { Write-Host "  $_" }
    Assert-True -Condition ($unloadExit -eq 0) -Message "unload exited with 0 (got $unloadExit)"

    Start-Sleep -Milliseconds 400

    $logLines = @()
    if (Test-Path $log) {
        $logLines = Get-Content $log
    }

    Assert-LogContains -Lines $logLines -Needle 'dllmain:detach' -Message 'DllMain ran (DLL_PROCESS_DETACH)'
    Assert-LogContains -Lines $logLines -Needle 'tls:detach' -Message 'TLS callback ran (DLL_PROCESS_DETACH)'
    Assert-True -Condition (($unloadOutput -join "`n") -match 'Removed image from the loader PC index') -Message 'loader PC index entry removed on unload'

    $afterUnload = & $vega --process target.exe --list 2>&1
    Assert-True -Condition (-not (($afterUnload -join "`n") -match 'sample\.dll')) -Message 'module record removed after unload'

    Assert-True -Condition (-not $target.HasExited) -Message 'target process survived map and unload'
}
finally {
    if (-not $target.HasExited) {
        Stop-Process -Id $target.Id -Force -ErrorAction SilentlyContinue
    }

    Remove-Item Env:\VEGA_TEST_LOG -ErrorAction SilentlyContinue
}

Write-Host ""

if ($failures.Count -eq 0) {
    Write-Host "RESULT: PASS" -ForegroundColor Green
    exit 0
}

Write-Host "RESULT: FAIL ($($failures.Count) assertion(s))" -ForegroundColor Red
foreach ($failure in $failures) {
    Write-Host "  - $failure"
}

exit 1
