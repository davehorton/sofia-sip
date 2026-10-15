#!/bin/bash
#
# Build sofia-sip and run its tests. The same script runs locally
# (directly on Linux, or via scripts/docker-test.sh) and in CI.
#
# usage: scripts/test.sh [gcc|clang|asan|all-gcc]
#
#   gcc      gcc build, gating test suites                 (default)
#   clang    clang build, gating test suites
#   asan     clang + AddressSanitizer/UndefinedBehaviorSanitizer,
#            gating test suites
#   all-gcc  gcc build, every module's tests, including the
#            modules drachtio does not use (informational)
#
# The source tree is copied to $BUILD_DIR (default /tmp/sofia-build-<mode>)
# so the checkout itself is never modified. Set JOBS to change -j.

set -euo pipefail

mode=${1:-gcc}
src=$(cd "$(dirname "$0")/.." && pwd)
build=${BUILD_DIR:-/tmp/sofia-build-$mode}
jobs=${JOBS:-$(nproc 2>/dev/null || echo 4)}

# Modules whose tests gate CI: the parts of the library drachtio uses.
# nua, soa, nea, nth, http, iptsec, sdp and stun still build, and their
# tests run with 'all-gcc', but they do not gate.
gating="su bnf ipt url msg sip sresolv tport nta"

case $mode in
  gcc|all-gcc)
    export CC=gcc CFLAGS="-g -O2 -Wall"
    ;;
  clang)
    export CC=clang CFLAGS="-g -O2 -Wall"
    ;;
  asan)
    # -fno-sanitize=function: header parsers are called through generic
    #   msg_hclass_t function pointers by design.
    # alignment, pointer-overflow, null: library idioms (char * used as
    #   url_string_t *, offsetof-style member access); see the test
    #   inventory notes before re-enabling.
    san="-fsanitize=address,undefined -fno-sanitize=function,alignment,pointer-overflow,null"
    export CC=clang
    export CFLAGS="-g -O1 -fno-omit-frame-pointer $san -fno-sanitize-recover=all"
    export LDFLAGS="$san"
    export ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}
    export UBSAN_OPTIONS=${UBSAN_OPTIONS:-print_stacktrace=1:halt_on_error=1}
    ;;
  *)
    echo "usage: $0 [gcc|clang|asan|all-gcc]" >&2
    exit 2
    ;;
esac

echo "== sofia-sip tests: mode=$mode src=$src build=$build"
mkdir -p "$build"
rsync -a --delete --exclude .git "$src/" "$build/"
cd "$build"

./bootstrap.sh > bootstrap.log 2>&1 || { cat bootstrap.log; exit 1; }
./configure --with-glib=no --disable-shared > configure.log 2>&1 || { cat configure.log; exit 1; }
make -j"$jobs" > make.log 2>&1 || { tail -50 make.log; exit 1; }

if grep -q "warning:" make.log; then
  echo "== compiler warnings:"
  grep "warning:" make.log | sort -u
fi

rc=0
if [ "$mode" = all-gcc ]; then
  make -k -j"$jobs" check || rc=$?
else
  for d in $gating; do
    echo "== make check: $d"
    make -C "libsofia-sip-ua/$d" -k -j"$jobs" check || rc=1
  done
fi

if [ $rc -ne 0 ]; then
  echo "== failing test logs:"
  for f in $(grep -lE "^:test-result: (FAIL|ERROR)" $(find libsofia-sip-ua -name '*.trs') 2>/dev/null); do
    log=${f%.trs}.log
    echo "---- $log"
    tail -60 "$log"
  done
fi

exit $rc
