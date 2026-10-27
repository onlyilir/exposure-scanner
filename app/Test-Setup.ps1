# Install test for release\Exposure-Scanner-Setup.exe that leaves the PC untouched: installs into a
# temp folder with shortcuts redirected (ES_TEST_LINK_DIR) and without the PATH / Apps-list
# changes, checks the files and their Windows file details, runs the installed command line, checks
# the portable zip, then uninstalls.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File app\Test-Setup.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$setup = Join-Path $root 'release\Exposure-Scanner-Setup.exe'
$payload = Join-Path $root 'release\payload'
$work = Join-Path $env:TEMP 'exposure-scanner-setup-test'
$script:run = 0; $script:fail = 0
function Check([bool]$ok, [string]$what) {
    $script:run++
    if (-not $ok) { $script:fail++; Write-Output "FAIL: $what" }
}

Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $work | Out-Null
$target = Join-Path $work 'Exposure Scanner'; $links = Join-Path $work 'links'
$version = [regex]::Match((Get-Content (Join-Path $PSScriptRoot 'App.cs') -Raw), 'const string Version = "([0-9.]+)"').Groups[1].Value

# 1. file details: every exe says who made it and which version it is
$details = @{ $setup = 'Exposure Scanner Setup'; (Join-Path $payload 'ExposureScanner.exe') = 'Exposure Scanner';
              (Join-Path $payload 'scanner.exe') = 'Exposure Scanner command line' }
foreach ($exe in $details.Keys) {
    $vi = (Get-Item $exe).VersionInfo
    Check ($vi.CompanyName -eq 'onlyilir') "$(Split-Path $exe -Leaf) publisher (was '$($vi.CompanyName)')"
    Check ($vi.ProductVersion -like "$version*") "$(Split-Path $exe -Leaf) version $version (was '$($vi.ProductVersion)')"
    Check ($vi.FileDescription -eq $details[$exe]) "$(Split-Path $exe -Leaf) description (was '$($vi.FileDescription)')"
    Check ($vi.LegalCopyright -like '*MIT*') "$(Split-Path $exe -Leaf) copyright"
}

# 2. install with the setup exe itself (the program files are inside it)
$env:ES_TEST_LINK_DIR = $links
$p = Start-Process $setup -ArgumentList "--quiet --target `"$target`" --no-path --no-registry" -Wait -PassThru
Check ($p.ExitCode -eq 0) "quiet install exit code 0 (was $($p.ExitCode))"
foreach ($f in 'ExposureScanner.exe', 'scanner.exe', 'README.txt', 'LICENSE.txt', 'THIRD-PARTY-NOTICES.txt', 'data\advisories.txt', 'data\spki_blocklist.txt') {
    $ok = (Test-Path (Join-Path $target $f)) -and
          ((Get-FileHash (Join-Path $target $f)).Hash -eq (Get-FileHash (Join-Path $payload $f)).Hash)
    Check $ok "installed $f, identical to the build"
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

# 4. update over an existing install (the setup again), and the portable zip has everything
$p = Start-Process $setup -ArgumentList "--quiet --target `"$target`" --no-path --no-registry" -Wait -PassThru
Check ($p.ExitCode -eq 0) 'reinstall over an existing install'
$zip = Join-Path $root "release\Exposure-Scanner-$version-portable.zip"
Check (Test-Path $zip) "portable zip for $version exists"
if (Test-Path $zip) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $z = [IO.Compression.ZipFile]::OpenRead($zip)
    $names = $z.Entries | ForEach-Object { $_.FullName.Replace([string][char]92, '/') } # backslash -> slash
    $z.Dispose()
    foreach ($f in 'ExposureScanner.exe', 'scanner.exe', 'README.txt', 'LICENSE.txt', 'THIRD-PARTY-NOTICES.txt', 'data/advisories.txt', 'data/spki_blocklist.txt') {
        Check ($names -contains $f) "portable zip contains $f"
    }
}

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
