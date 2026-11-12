#!/bin/sh
# Run every kflow test in one go.
#
#   sh tests/run_all.sh                      # downloads Debian's arm64 ext4 module package (377 KB, sha256 checked)
#                                            # into a temporary folder and tests on ext4.ko.xz
#   sh tests/run_all.sh vmlinux mod.ko ...   # or test on your own kernel ELFs / modules
#
# Needs Python 3.8+; the download needs curl, ar and tar. Nothing is installed. The IDA tests run the plugin on
# fake ida_* modules (no IDA needed). Set IDA_STUBS=<folder with ida_*.pyi>, e.g. the site-packages of an
# ida-hcli or idapro install, to also check every IDA API name kflow uses against the official stubs.
set -eu
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}
fails=0
run() {
    echo "== $*"
    if "$@"; then :; else echo "FAILED: $*"; fails=$((fails + 1)); fi
}

run "$PY" -I tests/test_core.py

if [ $# -eq 0 ]; then
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    deb=ext4-modules-6.12.94+deb13-arm64-di_6.12.94-1_arm64.udeb
    want=f7957d08ff7b2d63775a2b97897e1934de2066b9d668cad101fa09147d35aaa0
    echo "== downloading $deb"
    curl -sf -o "$tmp/$deb" "https://deb.debian.org/debian/pool/main/l/linux-signed-arm64/$deb"
    got=$("$PY" -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$tmp/$deb")
    [ "$got" = "$want" ] || { echo "sha256 mismatch for $deb: $got"; exit 1; }
    (cd "$tmp" && ar x "$deb" && tar -xf data.tar.xz)
    set -- "$tmp/lib/modules/6.12.94+deb13-arm64/kernel/fs/ext4/ext4.ko.xz"
fi

for f in "$@"; do
    for t in test_demo test_ida_stub test_headless_stub test_entry_stub test_warnflow_stub; do
        if [ -f "tests/$t.py" ]; then run "$PY" -I "tests/$t.py" "$f"; fi
    done
done

if [ -n "${IDA_STUBS:-}" ]; then
    run "$PY" -I tests/check_ida_api.py "$IDA_STUBS"
else
    echo "(IDA API names not checked: set IDA_STUBS=<folder with ida_*.pyi>)"
fi

if [ "$fails" -eq 0 ]; then echo "ALL PASSED"; else echo "$fails FAILED"; exit 1; fi
