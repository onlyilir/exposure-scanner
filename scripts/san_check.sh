#!/bin/bash
# AddressSanitizer + UBSan pass with MSYS2 clang64 (unit, scan, net, report tests + CLI checks).
# Run from PowerShell:
#   $env:MSYSTEM='CLANG64'; $env:CHERE_INVOKING='1'; C:\msys64\usr\bin\bash.exe -l scripts/san_check.sh
cd "$(dirname "$0")/.." || exit 2
clang --version | head -1
LIB="src/version.c src/advisory.c src/fsutil.c src/gitindex.c src/secret_scan.c src/pysupply.c"
NET="src/net_compat.c src/tls_audit.c src/http_probe.c src/webcheck.c src/techdetect.c src/vulndb.c src/maildns.c"
FL="-std=gnu99 -Wall -Wextra -Wpedantic -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer -pthread"
LD="-lssl -lcrypto -lws2_32 -lcrypt32 -ldnsapi"
clang $FL -o san_unit.exe tests/test_main.c src/version.c src/advisory.c 2>&1 | tail -8
clang $FL -o san_scan.exe tests/test_scan.c $LIB 2>&1 | tail -8
clang $FL -o san_net.exe tests/test_net.c src/advisory.c src/version.c $NET $LD 2>&1 | tail -8
clang $FL -o san_report.exe tests/test_report.c src/report.c src/report_html.c $LIB $NET $LD 2>&1 | tail -8
clang $FL -o san_tech.exe tests/test_tech.c src/report.c src/report_html.c $LIB $NET $LD 2>&1 | tail -8
clang $FL -o san_scanner.exe src/main.c src/report.c src/report_html.c $LIB $NET $LD 2>&1 | tail -8
./san_unit.exe data/advisories.txt 2>&1 | tail -3
./san_tech.exe 2>&1 | tail -20
./san_scan.exe data/advisories.txt 2>&1 | tail -6
./san_net.exe data/advisories.txt 2>&1 | tail -20
./san_report.exe data/advisories.txt 2>&1 | tail -20
# CLI checks with the sanitized scanner; ASan reports go to stderr, so keep a copy
SCANNER=./san_scanner.exe CHECKER=./san_report.exe NETTESTS=./san_net.exe ASAN_OPTIONS=log_path=tmp_asan \
    bash scripts/cli_check.sh
if ls tmp_asan* >/dev/null 2>&1; then
    echo "SANITIZER REPORTS from the CLI run:"
    cat tmp_asan*
    rm -f tmp_asan*
fi
rm -f san_unit.exe san_scan.exe san_net.exe san_report.exe san_tech.exe san_scanner.exe
echo "san pass finished"
