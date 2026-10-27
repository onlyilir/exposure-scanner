#!/bin/bash
# Writes THIRD-PARTY-NOTICES.txt from the license files MSYS2 installs for the libraries that the
# single-file scanner.exe links in (scripts/build_static.sh). Run in an MSYS2 UCRT64 shell.
cd "$(dirname "$0")/.." || exit 2
L=/ucrt64/share/licenses
ver() { pacman -Q "$1" 2>/dev/null | cut -d' ' -f2; }
{
    echo "Third-party software in Exposure Scanner"
    echo "========================================"
    echo
    echo "scanner.exe contains the following libraries. Their licenses follow."
    echo
    echo "- OpenSSL $(ver mingw-w64-ucrt-x86_64-openssl) (https://www.openssl.org) - Apache License 2.0"
    echo "- mingw-w64 winpthreads $(ver mingw-w64-ucrt-x86_64-libwinpthread) - MIT-style license"
    echo "- mingw-w64 runtime $(ver mingw-w64-ucrt-x86_64-crt) - Zope Public License 2.1 and others, see below"
    echo "- GCC runtime library (libgcc) - GPL v3 with the GCC Runtime Library Exception, which"
    echo "  places no conditions on programs compiled with GCC"
    echo
    echo "The desktop app uses the .NET Framework that is part of Windows."
    for f in "openssl/LICENSE:OpenSSL" "winpthreads/COPYING:mingw-w64 winpthreads" \
             "crt/COPYING:mingw-w64 runtime" "crt/COPYING.MinGW-w64-runtime.txt:mingw-w64 runtime (details)"; do
        echo
        echo "------------------------------------------------------------------------"
        echo "${f#*:}"
        echo "------------------------------------------------------------------------"
        echo
        cat "$L/${f%%:*}"
    done
} | sed 's/\r$//' > THIRD-PARTY-NOTICES.txt
echo "wrote THIRD-PARTY-NOTICES.txt ($(wc -l < THIRD-PARTY-NOTICES.txt) lines)"
