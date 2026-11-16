# Builds data\os_map.txt: which operating system releases shipped which upstream version of Apache,
# nginx, PHP and OpenSSL. A server answering "Apache/2.4.41 (Ubuntu)" can then be named as
# Ubuntu 20.04, and its end of life looked up. Distributions keep the upstream number and patch
# security holes themselves, so this table (not the upstream CVE list) is the right test for them.
# Sources (primary, read-only):
#   Ubuntu + Debian  Launchpad publishing history, https://api.launchpad.net/1.0/<distro>/+archive/primary
#   CentOS 6/7/8     https://vault.centos.org (final package trees)
#   RHEL 8/9/10 family  https://dl.rockylinux.org/pub/rocky/ (rebuilds of the RHEL packages)
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\Make-OsMap.ps1
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$root = Split-Path -Parent $PSScriptRoot
$out = New-Object Collections.Generic.SortedSet[string]

# release names as endoflife.date numbers them (https://wiki.ubuntu.com/Releases, https://www.debian.org/releases/)
$ubuntu = @{ lucid = '10.04'; precise = '12.04'; trusty = '14.04'; xenial = '16.04'; bionic = '18.04'; focal = '20.04';
             jammy = '22.04'; noble = '24.04'; oracular = '24.10'; plucky = '25.04'; questing = '25.10'; resolute = '26.04' }
$debian = @{ squeeze = '6'; wheezy = '7'; jessie = '8'; stretch = '9'; buster = '10'; bullseye = '11'; bookworm = '12'; trixie = '13' }
$sources = @{
    ubuntu = @{ apache = @('apache2'); nginx = @('nginx'); openssl = @('openssl')
                php = @('php5', 'php7.0', 'php7.2', 'php7.4', 'php8.1', 'php8.3', 'php8.4') }
    debian = @{ apache = @('apache2'); nginx = @('nginx'); openssl = @('openssl')
                php = @('php5', 'php7.0', 'php7.3', 'php7.4', 'php8.2', 'php8.4') }
}
foreach ($distro in 'ubuntu', 'debian') {
    $names = if ($distro -eq 'ubuntu') { $ubuntu } else { $debian }
    foreach ($product in $sources[$distro].Keys) {
        foreach ($src in $sources[$distro][$product]) {
            $url = "https://api.launchpad.net/1.0/$distro/+archive/primary?ws.op=getPublishedSources&source_name=$src&exact_match=true&ws.size=300"
            while ($url) {
                $page = Invoke-RestMethod -Uri $url -UseBasicParsing -TimeoutSec 120
                foreach ($e in $page.entries) {
                    $series = ($e.distro_series_link -split '/')[-1]
                    if (-not $names.ContainsKey($series)) { continue } # sid, experimental, unknown
                    # "2.4.41-4ubuntu3.14" / "7.4.3+dfsg-1" / "1:1.1.1f-1" -> upstream "2.4.41"
                    $v = ($e.source_package_version -replace '^\d+:', '') -replace '[+~-].*$', ''
                    if ($v -match '^\d+(\.\d+)+[a-z]?$') { [void]$out.Add("M`t$product`t$v`t$distro`t$($names[$series])") }
                }
                $url = $page.next_collection_link
            }
        }
    }
}

# RHEL family: version -> major release, from the package file names in the final trees
$trees = @(
    @('6', 'https://vault.centos.org/6.10/os/x86_64/Packages/'),
    @('6', 'https://vault.centos.org/6.10/updates/x86_64/Packages/'),
    @('7', 'https://vault.centos.org/7.9.2009/os/x86_64/Packages/'),
    @('7', 'https://vault.centos.org/7.9.2009/updates/x86_64/Packages/'),
    @('8', 'https://vault.centos.org/8.5.2111/AppStream/x86_64/os/Packages/'),
    @('8', 'https://vault.centos.org/8.5.2111/BaseOS/x86_64/os/Packages/'),
    @('9', 'https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/Packages/h/'),
    @('9', 'https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/Packages/n/'),
    @('9', 'https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/Packages/p/'),
    @('9', 'https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/Packages/o/'),
    @('10', 'https://dl.rockylinux.org/pub/rocky/10/AppStream/x86_64/os/Packages/h/'),
    @('10', 'https://dl.rockylinux.org/pub/rocky/10/AppStream/x86_64/os/Packages/n/'),
    @('10', 'https://dl.rockylinux.org/pub/rocky/10/AppStream/x86_64/os/Packages/p/'),
    @('10', 'https://dl.rockylinux.org/pub/rocky/10/BaseOS/x86_64/os/Packages/o/')
)
$rpm = @{ httpd = 'apache'; nginx = 'nginx'; php = 'php'; openssl = 'openssl' }
foreach ($t in $trees) {
    $html = (Invoke-WebRequest -Uri $t[1] -UseBasicParsing -TimeoutSec 180).Content
    foreach ($m in [regex]::Matches($html, 'href="(httpd|nginx|php|openssl)-(?:\d+:)?(\d+(?:\.\d+)+[a-z]?)-[^"]*\.rpm"')) {
        [void]$out.Add("M`t$($rpm[$m.Groups[1].Value])`t$($m.Groups[2].Value)`trhel`t$($t[0])")
    }
}

$header = @(
    '# Exposure Scanner OS map: upstream version shipped by an OS release. Built by scripts\Make-OsMap.ps1',
    "# on $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')) from Launchpad (Ubuntu, Debian), vault.centos.org and dl.rockylinux.org.",
    '# M product upstream-version distro release   (distro rhel = the RHEL family: RHEL, CentOS, Rocky, AlmaLinux)'
)
[IO.File]::WriteAllLines((Join-Path $root 'data\os_map.txt'), [string[]]($header + @($out)), (New-Object Text.UTF8Encoding($false)))
Write-Output "os_map.txt: $($out.Count) entries"
