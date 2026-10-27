#!/bin/bash
# Build + run everything with MSYS2 UCRT64 gcc (warnings on), then CLI smoke tests.
# Run from PowerShell:  $env:MSYSTEM='UCRT64'; $env:CHERE_INVOKING='1'; C:\msys64\usr\bin\bash.exe -l scripts/build_net.sh
cd "$(dirname "$0")/.." || exit 2
LIB="src/version.c src/advisory.c src/fsutil.c src/gitindex.c src/secret_scan.c src/pysupply.c"
NET="src/net_compat.c src/tls_audit.c src/http_probe.c src/webcheck.c"
FL="-std=gnu99 -Wall -Wextra -Wpedantic -pthread"
LD="-lssl -lcrypto -lws2_32 -lcrypt32"
set -e
echo "== gcc build =="
gcc $FL -O1 -o runtests.exe tests/test_main.c src/version.c src/advisory.c
gcc $FL -O1 -o scantests.exe tests/test_scan.c $LIB
gcc $FL -O1 -o nettests.exe tests/test_net.c src/advisory.c src/version.c $NET $LD
gcc $FL -O1 -o reporttests.exe tests/test_report.c src/report.c src/report_html.c $LIB $NET $LD
gcc $FL -O2 -o scanner.exe src/main.c src/report.c src/report_html.c $LIB $NET $LD
set +e
echo "== run =="
./runtests.exe data/advisories.txt 2>&1 | tail -1
./scantests.exe data/advisories.txt 2>&1 | tail -3
./nettests.exe data/advisories.txt 2>&1 | tail -8
./reporttests.exe data/advisories.txt 2>&1 | tail -12
SCANNER=./scanner.exe CHECKER=./reporttests.exe NETTESTS=./nettests.exe bash scripts/cli_check.sh
