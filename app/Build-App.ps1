# Builds the desktop app and its installer. No downloads: the engine uses MSYS2 (already set up),
# the app uses the .NET Framework compiler that ships with Windows, Setup.exe uses IExpress.
#   release\payload\                 ExposureScanner.exe, scanner.exe, data\, README.txt (runnable as is)
#   release\Exposure-Scanner-Setup.exe
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File app\Build-App.ps1 [-SkipEngine] [-NoSetup]
param([switch]$SkipEngine, [switch]$NoSetup)
$ErrorActionPreference = 'Stop'
$app = $PSScriptRoot
$root = Split-Path -Parent $app
$release = Join-Path $root 'release'
$payload = Join-Path $release 'payload'
New-Item -ItemType Directory -Force -Path $payload, (Join-Path $payload 'data') | Out-Null

# 1. engine: single-file scanner.exe (OpenSSL linked in)
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

# 3. desktop app (WPF, C# 5)
$fw = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$csc = Join-Path $fw 'csc.exe'
$refs = @('WPF\PresentationFramework.dll', 'WPF\PresentationCore.dll', 'WPF\WindowsBase.dll', 'System.Xaml.dll',
          'System.Web.Extensions.dll', 'Microsoft.CSharp.dll', 'System.Core.dll', 'System.dll') |
        ForEach-Object { '/reference:' + (Join-Path $fw $_) }
$cscArgs = @('/nologo', '/target:winexe', '/optimize+', '/codepage:65001', '/warn:4',
             ('/out:' + (Join-Path $payload 'ExposureScanner.exe')),
             ('/win32icon:' + (Join-Path $app 'app.ico')),
             ('/win32manifest:' + (Join-Path $app 'app.manifest')),
             ('/resource:' + (Join-Path $app 'Styles.xaml') + ',Styles.xaml'),
             ('/resource:' + (Join-Path $app 'MainWindow.xaml') + ',MainWindow.xaml'),
             ('/resource:' + (Join-Path $app 'SetupWindow.xaml') + ',SetupWindow.xaml')) + $refs + @((Join-Path $app 'App.cs'))
& $csc @cscArgs
if ($LASTEXITCODE -ne 0) { throw 'App build failed.' }

# 4. data and a short read-me
Copy-Item (Join-Path $root 'data\advisories.txt'), (Join-Path $root 'data\spki_blocklist.txt') (Join-Path $payload 'data') -Force
Set-Content -Path (Join-Path $payload 'README.txt') -Encoding ASCII -Value @'
Exposure Scanner
================
Website and code safety check-ups with plain-language reports.

Desktop app: open "Exposure Scanner" from the Start menu.
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
Write-Output "App built: $payload"
if ($NoSetup) { return }

# 5. Setup.exe (IExpress cannot hold folders, so the package is flat; the installer puts the
#    data files into data\). IExpress prefers paths without spaces, so it works in TEMP.
$stage = Join-Path $env:TEMP 'exposure-scanner-setup'
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
$pkg = Join-Path $stage 'pkg'
New-Item -ItemType Directory -Force -Path $pkg | Out-Null
$files = @('ExposureScanner.exe', 'scanner.exe', 'README.txt', 'LICENSE.txt', 'THIRD-PARTY-NOTICES.txt')
foreach ($f in $files) { Copy-Item (Join-Path $payload $f) $pkg }
Copy-Item (Join-Path $payload 'data\advisories.txt'), (Join-Path $payload 'data\spki_blocklist.txt') $pkg
$all = $files + @('advisories.txt', 'spki_blocklist.txt')
$exeTmp = Join-Path $stage 'Exposure-Scanner-Setup.exe'
$sed = Join-Path $stage 'setup.sed'
$strings = ''; $list = ''
for ($i = 0; $i -lt $all.Count; $i++) { $strings += "FILE$i=`"$($all[$i])`"`r`n"; $list += "%FILE$i%=`r`n" }
Set-Content -LiteralPath $sed -Encoding ASCII -Value @"
[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=1
HideExtractAnimation=1
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=%InstallPrompt%
DisplayLicense=%DisplayLicense%
FinishMessage=%FinishMessage%
TargetName=%TargetName%
FriendlyName=%FriendlyName%
AppLaunched=%AppLaunched%
PostInstallCmd=%PostInstallCmd%
AdminQuietInstCmd=%AdminQuietInstCmd%
UserQuietInstCmd=%UserQuietInstCmd%
SourceFiles=SourceFiles
[Strings]
InstallPrompt=
DisplayLicense=
FinishMessage=
TargetName=$exeTmp
FriendlyName=Exposure Scanner Setup
AppLaunched=ExposureScanner.exe --install
PostInstallCmd=<None>
AdminQuietInstCmd=
UserQuietInstCmd=
$strings[SourceFiles]
SourceFiles0=$pkg\
[SourceFiles0]
$list
"@
$p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\iexpress.exe') -ArgumentList @('/N', '/Q', '/M', $sed) -Wait -PassThru -WindowStyle Hidden
if (-not (Test-Path -LiteralPath $exeTmp)) { throw "IExpress did not produce the setup exe (exit code $($p.ExitCode))." }
$setup = Join-Path $release 'Exposure-Scanner-Setup.exe'
Copy-Item -LiteralPath $exeTmp -Destination $setup -Force
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
Write-Output ("Setup written: {0} ({1:N1} MB)" -f $setup, ((Get-Item $setup).Length / 1MB))
