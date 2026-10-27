# Builds the desktop app, its installer and a portable zip. No downloads: the engine uses MSYS2,
# the app and the installer use the .NET Framework compiler that ships with Windows.
#   release\payload\                          ExposureScanner.exe, scanner.exe, data\, read-me, licenses
#   release\Exposure-Scanner-Setup.exe         the app built with /define:SETUP and the payload inside it
#   release\Exposure-Scanner-<ver>-portable.zip
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File app\Build-App.ps1 [-SkipEngine] [-NoSetup]
param([switch]$SkipEngine, [switch]$NoSetup)
$ErrorActionPreference = 'Stop'
$app = $PSScriptRoot
$root = Split-Path -Parent $app
$release = Join-Path $root 'release'
$payload = Join-Path $release 'payload'
New-Item -ItemType Directory -Force -Path $payload, (Join-Path $payload 'data') | Out-Null
$version = [regex]::Match((Get-Content (Join-Path $app 'App.cs') -Raw), 'const string Version = "([0-9.]+)"').Groups[1].Value

# 1. engine: single-file scanner.exe (OpenSSL linked in, version info and icon)
if (-not $SkipEngine) {
    $posix = '/' + $root.Substring(0, 1).ToLower() + ($root.Substring(2) -replace '\\', '/')
    $env:MSYSTEM = 'UCRT64'; $env:CHERE_INVOKING = '1'
    & C:\msys64\usr\bin\bash.exe -l "$posix/scripts/build_static.sh"
    if ($LASTEXITCODE -ne 0) { throw 'Engine build failed.' }
}
if (-not (Test-Path (Join-Path $payload 'scanner.exe'))) { throw 'release\payload\scanner.exe is missing; run without -SkipEngine.' }

# 2. icon
if (-not (Test-Path (Join-Path $app 'app.ico'))) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $app 'Make-Icon.ps1')
}

# 3. desktop app (WPF, C# 5); the installer is the same source with SETUP defined
$fw = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$csc = Join-Path $fw 'csc.exe'
$refs = @('WPF\PresentationFramework.dll', 'WPF\PresentationCore.dll', 'WPF\WindowsBase.dll', 'System.Xaml.dll',
          'System.Web.Extensions.dll', 'Microsoft.CSharp.dll', 'System.Core.dll', 'System.dll') |
        ForEach-Object { '/reference:' + (Join-Path $fw $_) }
function Invoke-Csc([string]$out, [string[]]$extra) {
    $cscArgs = @('/nologo', '/target:winexe', '/optimize+', '/codepage:65001', '/warn:4', ('/out:' + $out),
                 ('/win32icon:' + (Join-Path $app 'app.ico')),
                 ('/win32manifest:' + (Join-Path $app 'app.manifest')),
                 ('/resource:' + (Join-Path $app 'Styles.xaml') + ',Styles.xaml'),
                 ('/resource:' + (Join-Path $app 'MainWindow.xaml') + ',MainWindow.xaml'),
                 ('/resource:' + (Join-Path $app 'SetupWindow.xaml') + ',SetupWindow.xaml')) + $extra + $refs +
               @((Join-Path $app 'App.cs'))
    & $csc @cscArgs
    if ($LASTEXITCODE -ne 0) { throw "Build of $out failed." }
}
Invoke-Csc (Join-Path $payload 'ExposureScanner.exe') @()

# 4. data, a short read-me and the licenses
Copy-Item (Join-Path $root 'data\advisories.txt'), (Join-Path $root 'data\spki_blocklist.txt') (Join-Path $payload 'data') -Force
Set-Content -Path (Join-Path $payload 'README.txt') -Encoding ASCII -Value @'
Exposure Scanner
================
Website and code safety check-ups with plain-language reports.

Desktop app: open "Exposure Scanner" from the Start menu (portable zip: run ExposureScanner.exe).
Command line: open a new Command Prompt or PowerShell window and type
    scanner site shop.com --i-own-this --html report.html
    scanner secrets C:\code\my-project
    scanner              (lists every command)

Only check websites whose owner has given you permission. A permission form
template: https://github.com/onlyilir/exposure-scanner/blob/main/docs/permission-form.md
Reports from the app are saved in Documents\Exposure Scanner\Reports.
Uninstall: Windows Settings > Apps > Exposure Scanner.

Free and open source (MIT license, see LICENSE.txt; bundled libraries in
THIRD-PARTY-NOTICES.txt). Source and new versions:
    https://github.com/onlyilir/exposure-scanner
If it saves you time: https://buymeacoffee.com/only.ilir
'@
Copy-Item (Join-Path $root 'LICENSE') (Join-Path $payload 'LICENSE.txt') -Force
Copy-Item (Join-Path $root 'THIRD-PARTY-NOTICES.txt') (Join-Path $payload 'THIRD-PARTY-NOTICES.txt') -Force
Write-Output "App built: $payload (version $version)"
if ($NoSetup) { return }

# 5. Exposure-Scanner-Setup.exe: the app with every program file gzip-compressed inside it as a
#    resource "payload/<name>.gz". No self-extractor (IExpress), nothing unpacked to TEMP.
$stage = Join-Path $env:TEMP 'exposure-scanner-setup'
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stage | Out-Null
$files = @{
    'ExposureScanner.exe' = 'ExposureScanner.exe'; 'scanner.exe' = 'scanner.exe'; 'README.txt' = 'README.txt'
    'LICENSE.txt' = 'LICENSE.txt'; 'THIRD-PARTY-NOTICES.txt' = 'THIRD-PARTY-NOTICES.txt'
    'advisories.txt' = 'data\advisories.txt'; 'spki_blocklist.txt' = 'data\spki_blocklist.txt'
}
$resArgs = @()
foreach ($name in $files.Keys) {
    $gz = Join-Path $stage "$name.gz"
    $in = [IO.File]::OpenRead((Join-Path $payload $files[$name]))
    $out = [IO.File]::Create($gz)
    $zip = New-Object IO.Compression.GZipStream($out, [IO.Compression.CompressionLevel]::Optimal)
    $in.CopyTo($zip); $zip.Dispose(); $out.Dispose(); $in.Dispose()
    $resArgs += ('/resource:' + $gz + ',payload/' + $name + '.gz')
}
$setup = Join-Path $release 'Exposure-Scanner-Setup.exe'
Invoke-Csc $setup (@('/define:SETUP') + $resArgs)
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
Write-Output ("Setup written: {0} ({1:N1} MB)" -f $setup, ((Get-Item $setup).Length / 1MB))

# 6. portable zip: the payload folder as it is (runs from anywhere; no Start menu, PATH or Apps entry)
$zipPath = Join-Path $release "Exposure-Scanner-$version-portable.zip"
Remove-Item $zipPath -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $payload '*') -DestinationPath $zipPath
Write-Output ("Portable zip written: {0} ({1:N1} MB)" -f $zipPath, ((Get-Item $zipPath).Length / 1MB))
