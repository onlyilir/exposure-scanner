#!/bin/bash
# Single-file scanner.exe for the installer: OpenSSL and the C runtime helpers linked in, so it
# runs on a PC without MSYS2. Output: release/payload/scanner.exe
# Run from PowerShell:  $env:MSYSTEM='UCRT64'; $env:CHERE_INVOKING='1'; C:\msys64\usr\bin\bash.exe -l scripts/build_static.sh
cd "$(dirname "$0")/.." || exit 2
SRC="src/main.c src/report.c src/report_html.c src/version.c src/advisory.c src/fsutil.c
     src/gitindex.c src/secret_scan.c src/pysupply.c src/net_compat.c src/tls_audit.c
     src/http_probe.c src/webcheck.c"
mkdir -p release/payload
set -e
gcc -std=gnu99 -Wall -Wextra -Wpedantic -O2 -static -pthread -o release/payload/scanner.exe $SRC \
    -lssl -lcrypto -lws2_32 -lcrypt32 -lgdi32 -ladvapi32 -luser32
strip release/payload/scanner.exe
echo "built release/payload/scanner.exe ($(du -k release/payload/scanner.exe | cut -f1) KB)"
echo "DLLs it needs (all should be Windows system DLLs):"
objdump -p release/payload/scanner.exe | grep "DLL Name" | sed 's/^\s*/  /'
