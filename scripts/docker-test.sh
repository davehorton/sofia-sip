#!/bin/bash
#
# Run the sofia-sip tests in the same Docker image CI uses.
#
# usage: scripts/docker-test.sh [mode ...]
#
# Modes are those of scripts/test.sh (gcc, clang, asan, all-gcc); the
# default runs gcc, clang and asan in turn. The checkout is mounted
# read-only; builds happen inside the container.

set -euo pipefail

src=$(cd "$(dirname "$0")/.." && pwd)
image=${SOFIA_CI_IMAGE:-sofia-sip-ci}
modes=${*:-gcc clang asan}

docker build -q -t "$image" -f "$src/ci/Dockerfile" "$src/ci" > /dev/null

rc=0
for mode in $modes; do
  docker run --rm -v "$src:/src:ro" "$image" /src/scripts/test.sh "$mode" || rc=1
done

exit $rc
