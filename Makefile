# Thin wrapper for Linux/macOS or an MSYS2 shell (UCRT64 for `make`, CLANG64 for `make san`).
# On Windows the scripts in scripts/ are the reference build; this calls the same steps.
# Needs gcc (or clang) and OpenSSL 3 development files.
CC ?= gcc
WARN = -std=gnu99 -Wall -Wextra -Wpedantic -pthread
LIB = src/version.c src/advisory.c src/fsutil.c src/gitindex.c src/secret_scan.c src/pysupply.c
NET = src/net_compat.c src/tls_audit.c src/http_probe.c src/webcheck.c
ifeq ($(OS),Windows_NT)
LDLIBS = -lssl -lcrypto -lws2_32 -lcrypt32
X = .exe
else
LDLIBS = -lssl -lcrypto
X =
endif
# Some antivirus programs block exe names such as test_main.exe or unittests.exe; keep these names.
BINS = runtests$(X) scantests$(X) nettests$(X) reporttests$(X) scanner$(X)

.PHONY: all test san clean

all: scanner$(X)

scanner$(X): src/main.c src/report.c src/report_html.c $(LIB) $(NET)
	$(CC) $(WARN) -O2 -o $@ src/main.c src/report.c src/report_html.c $(LIB) $(NET) $(LDLIBS)

test: $(BINS)
	./runtests$(X) data/advisories.txt
	./scantests$(X) data/advisories.txt
	./nettests$(X) data/advisories.txt
	./reporttests$(X) data/advisories.txt
	SCANNER=./scanner$(X) CHECKER=./reporttests$(X) NETTESTS=./nettests$(X) bash scripts/cli_check.sh

runtests$(X): tests/test_main.c src/version.c src/advisory.c
	$(CC) $(WARN) -O1 -o $@ $^
scantests$(X): tests/test_scan.c $(LIB)
	$(CC) $(WARN) -O1 -o $@ $^
nettests$(X): tests/test_net.c src/advisory.c src/version.c $(NET)
	$(CC) $(WARN) -O1 -o $@ $^ $(LDLIBS)
reporttests$(X): tests/test_report.c src/report.c src/report_html.c $(LIB) $(NET)
	$(CC) $(WARN) -O1 -o $@ $^ $(LDLIBS)

san:
	bash scripts/san_check.sh

clean:
	rm -f $(BINS) san_*$(X) tmp_cli.out tmp_report_out.txt tmp_cli_report.html tmp_ports.txt
	rm -rf tmp_scan_test tmp_py_test tmp_report_fixture
