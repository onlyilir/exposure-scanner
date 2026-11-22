#!/bin/bash
# Fuzzes the parsers that read website and DNS data (tests/fuzz_parsers.c) with libFuzzer,
# AddressSanitizer and UBSan. Needs MSYS2 CLANG64 (clang + openssl). Seeds are written to
# tmp_fuzz/seeds; crashes, if any, are saved as tmp_fuzz/crash-*.
# Run from PowerShell:
#   $env:MSYSTEM='CLANG64'; $env:CHERE_INVOKING='1'; C:\msys64\usr\bin\bash.exe -l scripts/fuzz.sh [seconds]
cd "$(dirname "$0")/.." || exit 2
SECONDS_TO_RUN=${1:-180}
NET="src/net_compat.c src/tls_audit.c src/http_probe.c src/webcheck.c src/techdetect.c src/vulndb.c src/maildns.c"
mkdir -p tmp_fuzz/seeds tmp_fuzz/corpus
printf 'Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16\r\nX-Powered-By: PHP/7.4.33-1+deb11u5\r\nVary: RSC\n\n<meta name="generator" content="WordPress 7.0.1"><link href="/wp-includes/css/dist/block-library/style.min.css?ver=7.0.1">' > tmp_fuzz/seeds/wp
printf 'X-Generator: Drupal 10 (https://www.drupal.org)\n\n<script src="/_next/static/chunks/main-1.js"></script><script id="__NEXT_DATA__">{}</script>window.next={version:"15.5.4",appDir:!0};version:function(){return B}let B="14.2.3"' > tmp_fuzz/seeds/next
printf 'Server: Microsoft-IIS/8.5\n\nV\twordpress\tCVE-1\tcritical\t9\t1\t>=6.9,<6.9.5;=4.7.1\t6.9.5\turl\tx\nS\twordpress\t7.0.1\tinsecure\nE\tphp\t7.4\t2022-11-28\t-\t7.4.33\nM\tapache\t2.4.6\trhel\t7\n' > tmp_fuzz/seeds/data
printf 'v=spf1 include:_spf.example ~all\n\nv=DMARC1; p=reject; rua=mailto:x@example\n5\r\nhello\r\n0\r\n\r\n' > tmp_fuzz/seeds/mail
set -e
# the clang driver refuses -fsanitize=fuzzer for MinGW, so the coverage flags and libFuzzer go in by hand
FUZZLIB="$(clang -print-resource-dir)/lib/windows/libclang_rt.fuzzer-x86_64.a"
clang -std=gnu99 -g -O1 -fsanitize=address,undefined -fsanitize-coverage=inline-8bit-counters,pc-table,trace-cmp \
    -fno-omit-frame-pointer -pthread -o tmp_fuzz/fuzz_parsers.exe tests/fuzz_parsers.c $NET src/advisory.c \
    src/version.c "$FUZZLIB" -lssl -lcrypto -lws2_32 -lcrypt32 -ldnsapi -lc++
set +e
cd tmp_fuzz
./fuzz_parsers.exe corpus seeds -max_total_time="$SECONDS_TO_RUN" -max_len=16384 -print_final_stats=1 2>&1 | \
    grep -E "^#[0-9]+ +(DONE|INITED)|stat::number_of_executed_units|stat::peak_rss_mb|ERROR|SUMMARY|crash-|Test unit written" | tail -12
ls crash-* leak-* timeout-* 2>/dev/null && { echo "FUZZING FOUND A PROBLEM"; exit 1; }
echo "fuzzing finished: no crashes"
