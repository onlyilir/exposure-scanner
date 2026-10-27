#!/bin/bash
# CLI smoke tests: exit codes, option checks and JSON validity. Local only: network targets are
# 127.0.0.1 port 1 (nothing listens there), so no request leaves this machine.
# Needs SCANNER and CHECKER (a reporttests binary) in the environment; called by the build scripts.
cd "$(dirname "$0")/.." || exit 2
: "${SCANNER:?}" "${CHECKER:?}"
pass=0
fail=0
OUT=tmp_cli.out

# expect <exit code> <json: 1 to validate stdout> <args...>
expect() {
    local want=$1 json=$2
    shift 2
    "$SCANNER" "$@" >"$OUT" 2>/dev/null
    local got=$?
    if [ "$got" -ne "$want" ]; then
        echo "FAIL (exit $got, want $want): scanner $*"
        fail=$((fail + 1))
    elif [ "$json" = 1 ] && ! "$CHECKER" --check-json "$OUT" >/dev/null; then
        echo "FAIL (invalid JSON): scanner $*"
        fail=$((fail + 1))
    else
        pass=$((pass + 1))
    fi
}

expect 2 0
expect 2 0 nonsense src
expect 0 0 secrets src
expect 0 1 secrets src --json
expect 2 0 secrets does-not-exist
expect 2 0 secrets src extra-arg
expect 2 0 secrets src --advisories data/advisories.txt # option not valid for secrets
expect 0 1 py src --json
expect 2 0 py src --rate 5
expect 2 0 py src --advisories does-not-exist.txt
expect 0 1 all src --json
expect 0 0 all src
expect 2 0 all src --http 127.0.0.1:1                    # no --i-own-this
expect 2 0 all src --tls 127.0.0.1:1                     # no --i-own-this
expect 2 0 all src --http                                # missing value
expect 2 0 all src --http 127.0.0.1:1 --i-own-this --threads 99
expect 2 1 all src --http 127.0.0.1:1 --tls 127.0.0.1:1 --i-own-this --timeout 500 --json
expect 2 0 http 127.0.0.1:1
expect 2 1 http 127.0.0.1:1 --i-own-this --timeout 500 --json
expect 2 1 tls 127.0.0.1:1 --i-own-this --timeout 500 --json
expect 2 0 tls 127.0.0.1:1 --timeout 500                 # no --i-own-this
expect 2 0 tls 127.0.0.1:1 127.0.0.1:2 --i-own-this      # tls takes one target
expect 2 0 tls 127.0.0.1:1 --i-own-this --rate 5         # not a tls option
if "$SCANNER" tls 127.0.0.1:1 --timeout 500 2>&1 | grep -q "refusing to run"; then
    pass=$((pass + 1))
else
    echo "FAIL: tls without --i-own-this did not refuse"
    fail=$((fail + 1))
fi
expect 2 0 site 127.0.0.1                                # no --i-own-this
expect 2 0 site --i-own-this                             # no site
expect 2 0 site 127.0.0.1 --i-own-this --client X        # --client needs --html
expect 2 0 secrets src --by X                            # --by needs --html
expect 2 0 all                                           # nothing to check
expect 2 1 all --site 127.0.0.1:1 --i-own-this --timeout 500 --json
expect 2 0 site 127.0.0.1:1 --i-own-this --timeout 500 --html tmp_cli_report.html --client "T"
if grep -q "Not ready to send" tmp_cli_report.html 2>/dev/null; then
    pass=$((pass + 1))
else
    echo "FAIL: --html report missing or lacks the not-ready warning"
    fail=$((fail + 1))
fi
expect 0 0 secrets src --html tmp_cli_report.html --by "Tester"
if grep -q "Prepared by Tester" tmp_cli_report.html 2>/dev/null &&
    ! grep -q "Not ready to send" tmp_cli_report.html; then
    pass=$((pass + 1))
else
    echo "FAIL: clean --html report"
    fail=$((fail + 1))
fi
expect 2 0 secrets src --html no-such-dir/x.html          # cannot write the report
# accented names (Albanian ë, ç; French é) reach the report as UTF-8, not as U+FFFD
expect 0 0 secrets src --html tmp_cli_report.html --client "Kafe Ëlira & Çaj" --by "René"
if grep -qF "Kafe Ëlira &amp; Çaj" tmp_cli_report.html && grep -qF "Prepared by René" tmp_cli_report.html &&
    ! grep -qF $'\xef\xbf\xbd' tmp_cli_report.html; then
    pass=$((pass + 1))
else
    echo "FAIL: accented client/by names were not kept in the report"
    fail=$((fail + 1))
fi
rm -f tmp_cli_report.html

# End to end, local only: a plain server on 127.0.0.1 answers 301 to a local https server; the
# scanner must follow that same-host redirect once and read the page settings there.
if [ -n "${NETTESTS:-}" ]; then
    rm -f tmp_ports.txt
    "$NETTESTS" --serve-redirect >tmp_ports.txt 2>/dev/null &
    srv=$!
    for _ in $(seq 100); do
        [ -s tmp_ports.txt ] && break
        sleep 0.1
    done
    port=$(head -1 tmp_ports.txt 2>/dev/null)
    "$SCANNER" all --http "http://127.0.0.1:$port" --i-own-this --timeout 3000 --json \
        >"$OUT" 2>/dev/null
    got=$?
    wait "$srv"
    srv_rc=$?
    for needle in '"redirected_from":"http://127.0.0.1:'"$port"'"' \
        '"id":"https_redirect","level":"ok"' '"id":"hsts","level":"ok"' \
        '"id":"nosniff","level":"ok"' '"id":"frame","level":"recommended"'; do
        if [ -n "$port" ] && grep -qF "$needle" "$OUT"; then
            pass=$((pass + 1))
        else
            echo "FAIL: redirect test JSON lacks $needle"
            fail=$((fail + 1))
        fi
    done
    if [ "$got" -eq 0 ] && [ "$srv_rc" -eq 0 ]; then
        pass=$((pass + 1))
    else
        echo "FAIL: redirect test exit $got (want 0), server exit $srv_rc (want 0)"
        fail=$((fail + 1))
    fi
    rm -f tmp_ports.txt
fi

# JSON content spot checks
"$SCANNER" all src --http 127.0.0.1:1 --tls 127.0.0.1:1 --i-own-this --timeout 500 --json \
    >"$OUT" 2>/dev/null
for needle in '"command":"all"' '"secrets":{"status":"clean"' '"python":{"status":"clean"' \
    '"http":{"status":"error"' '"tls":{"status":"error"' '"result":false' '"exit_code":2}'; do
    if grep -qF "$needle" "$OUT"; then
        pass=$((pass + 1))
    else
        echo "FAIL: JSON lacks $needle"
        fail=$((fail + 1))
    fi
done
rm -f "$OUT"
echo "cli: $((pass + fail)) checks, $fail failed"
[ "$fail" -eq 0 ]
