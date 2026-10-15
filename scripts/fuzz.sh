#!/bin/bash
#
# Build and run the libFuzzer targets in fuzz/.
#
# usage: scripts/fuzz.sh [SECONDS [TARGET ...]]
#
#   SECONDS  how long to fuzz each target (default 60)
#   TARGET   any of: sip_msg url ws sres stun (default: all)
#
# Builds an ASan+UBSan+libFuzzer-instrumented copy of the library in
# $BUILD_DIR (default /tmp/sofia-build-fuzz), then runs each target on
# its corpus in fuzz/corpus/<target>. New inputs found during the run go
# to $BUILD_DIR/corpus/<target> (the checkout is not modified); crashes
# are saved to $BUILD_DIR/crashes/<target> and fail the run.
#
# Needs clang with the libFuzzer and sanitizer runtimes, e.g. the image
# from ci/Dockerfile (scripts/docker-fuzz.sh runs it there).

set -euo pipefail

secs=${1:-60}
shift || true
targets=${*:-sip_msg url ws sres stun}
src=$(cd "$(dirname "$0")/.." && pwd)
build=${BUILD_DIR:-/tmp/sofia-build-fuzz}
jobs=${JOBS:-$(nproc 2>/dev/null || echo 4)}

san="-fsanitize=address,undefined -fno-sanitize=function,alignment,pointer-overflow,null"
export CC=clang
export CFLAGS="-g -O1 -fno-omit-frame-pointer $san -fsanitize=fuzzer-no-link -fno-sanitize-recover=all"
export LDFLAGS="$san"
export ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}
export UBSAN_OPTIONS=${UBSAN_OPTIONS:-print_stacktrace=1:halt_on_error=1}

echo "== building instrumented library in $build"
mkdir -p "$build"
rsync -a --no-owner --no-group --delete --exclude .git \
  --exclude /crashes --exclude /corpus --exclude /bin --exclude /fuzz-out \
  "$src/" "$build/"
cd "$build"
if [ ! -f Makefile ]; then
  ./bootstrap.sh > bootstrap.log 2>&1 || { cat bootstrap.log; exit 1; }
  ./configure --with-glib=no --disable-shared > configure.log 2>&1 ||
    { cat configure.log; exit 1; }
fi
make -j"$jobs" > make.log 2>&1 || { tail -50 make.log; exit 1; }

L=$build/libsofia-sip-ua
inc="-I$build -I$L/su -I$L/msg -I$L/sip -I$L/url -I$L/bnf -I$L/ipt -I$L/sresolv -I$L/tport -I$L/stun -I$L/features"
lib="$L/.libs/libsofia-sip-ua.a -lssl -lcrypto -lpthread"
mkdir -p bin

for t in $targets; do
  echo "== building fuzz_$t"
  case $t in
    sres) extra="-I$L/sresolv" ;;   # includes sres.c
    *)    extra="" ;;
  esac
  clang -g -O1 -fno-omit-frame-pointer $san -fsanitize=fuzzer $inc $extra \
    "$src/fuzz/fuzz_$t.c" $lib -o "bin/fuzz_$t"
done

rc=0
for t in $targets; do
  echo "== fuzzing fuzz_$t for ${secs}s"
  mkdir -p "corpus/$t" "crashes/$t"
  dict=""
  [ -f "$src/fuzz/$t.dict" ] && dict="-dict=$src/fuzz/$t.dict"
  # The checked-in corpus is read-only input; new units go to corpus/$t
  if ! "bin/fuzz_$t" -max_total_time="$secs" -rss_limit_mb=2048 \
       -timeout=10 -print_final_stats=1 $dict \
       -artifact_prefix="crashes/$t/" \
       "corpus/$t" "$src/fuzz/corpus/$t" > "fuzz_$t.log" 2>&1; then
    echo "!! fuzz_$t found a problem:"
    grep -E "ERROR: |runtime error|SUMMARY|^    #[0-9]+ " "fuzz_$t.log" | head -40
    ls -1 "crashes/$t"
    rc=1
  else
    grep -E "^stat::number_of_executed_units|^#[0-9]+.*DONE" "fuzz_$t.log" | tail -2
  fi
done

exit $rc
