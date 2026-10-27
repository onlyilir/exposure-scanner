# Install test for release\Exposure-Scanner-Setup.exe that leaves the PC untouched: unpacks the
# setup, installs into a temp folder with shortcuts redirected (ES_TEST_LINK_DIR) and without the
# PATH / Apps-list changes, runs the installed command line, then uninstalls.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File app\Test-Setup.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$setup = Join-Path $root 'release\Exposure-Scanner-Setup.exe'
$work = Join-Path $env:TEMP 'exposure-scanner-setup-test'
$script:run = 0; $script:fail = 0
function Check([bool]$ok, [string]$what) {
    $script:run++
    if (-not $ok) { $script:fail++; Write-Output "FAIL: $what" }
}

Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $work | Out-Null
$unpacked = Join-Path $work 'unpacked'; $target = Join-Path $work 'Exposure Scanner'; $links = Join-Path $work 'links'

# 1. the package holds all its files (IExpress: /T extracts, /C without running anything)
$p = Start-Process $setup -ArgumentList "/T:`"$unpacked`" /C /Q" -Wait -PassThru
foreach ($f in 'ExposureScanner.exe', 'scanner.exe', 'README.txt', 'LICENSE.txt', 'THIRD-PARTY-NOTICES.txt', 'advisories.txt', 'spki_blocklist.txt') {
    Check (Test-Path (Join-Path $unpacked $f)) "package contains $f"
}

# 2. install from the unpacked package
$env:ES_TEST_LINK_DIR = $links
$p = Start-Process (Join-Path $unpacked 'ExposureScanner.exe') -ArgumentList "--install --quiet --target `"$target`" --no-path --no-registry" -Wait -PassThru
Check ($p.ExitCode -eq 0) "quiet install exit code 0 (was $($p.ExitCode))"
foreach ($f in 'ExposureScanner.exe', 'scanner.exe', 'README.txt', 'LICENSE.txt', 'THIRD-PARTY-NOTICES.txt', 'data\advisories.txt', 'data\spki_blocklist.txt') {
    Check (Test-Path (Join-Path $target $f)) "installed $f"
}
Check (Test-Path (Join-Path $links 'start-menu\Exposure Scanner.lnk')) 'Start menu shortcut'
Check (Test-Path (Join-Path $links 'desktop\Exposure Scanner.lnk')) 'desktop shortcut'
if (Test-Path (Join-Path $links 'start-menu\Exposure Scanner.lnk')) {
    $sh = New-Object -ComObject WScript.Shell
    $lnk = $sh.CreateShortcut((Join-Path $links 'start-menu\Exposure Scanner.lnk'))
    Check ($lnk.TargetPath -eq (Join-Path $target 'ExposureScanner.exe')) "shortcut points at the installed app ($($lnk.TargetPath))"
}

# 3. the installed command line works from another folder, without MSYS2 on PATH
$savedPath = $env:PATH
$env:PATH = "$target;$env:SystemRoot\System32;$env:SystemRoot"
Push-Location $env:TEMP
$out = & scanner.exe py (Join-Path $root 'src') 2>&1 | Out-String
$code = $LASTEXITCODE
$json = & scanner.exe secrets (Join-Path $root 'src') --json 2>&1 | Out-String
Pop-Location
$env:PATH = $savedPath
Check ($code -eq 0) "installed scanner py exit 0 (was $code): $out"
Check ($out -notmatch 'cannot read advisories') 'installed scanner finds its data folder'
Check ($json -match '"summary":\{"important":0') 'installed scanner prints the JSON summary'

# 4. update over an existing install (same files again)
$p = Start-Process (Join-Path $unpacked 'ExposureScanner.exe') -ArgumentList "--install --quiet --target `"$target`" --no-path --no-registry" -Wait -PassThru
Check ($p.ExitCode -eq 0) 'reinstall over an existing install'

# 5. uninstall with the installed copy (it removes its own folder a moment after exiting)
$p = Start-Process (Join-Path $target 'ExposureScanner.exe') -ArgumentList "--uninstall --quiet --target `"$target`" --no-path --no-registry" -Wait -PassThru
Check ($p.ExitCode -eq 0) "quiet uninstall exit code 0 (was $($p.ExitCode))"
Check (-not (Test-Path (Join-Path $links 'start-menu\Exposure Scanner.lnk'))) 'Start menu shortcut removed'
Check (-not (Test-Path (Join-Path $links 'desktop\Exposure Scanner.lnk'))) 'desktop shortcut removed'
$gone = $false
for ($i = 0; $i -lt 30 -and -not $gone; $i++) { Start-Sleep -Milliseconds 300; $gone = -not (Test-Path $target) }
Check $gone 'install folder removed after uninstall'

Remove-Item Env:\ES_TEST_LINK_DIR
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
Write-Output "setup tests: $script:run checks, $script:fail failed"
if ($script:fail -gt 0) { exit 1 }
