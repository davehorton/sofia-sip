#!/bin/bash
#
# Run the fuzz targets in the same Docker image CI uses.
#
# usage: scripts/docker-fuzz.sh [SECONDS [TARGET ...]]
#
# Arguments are those of scripts/fuzz.sh. Build output, new corpus units
# and crash reproducers are kept in ./fuzz-out (git-ignored), so a crash
# can be inspected and replayed after the run, e.g.
#
#   scripts/docker-fuzz.sh 300 ws
#   fuzz-out/build/bin/fuzz_ws fuzz-out/build/crashes/ws/crash-...  (in the image)

set -euo pipefail

src=$(cd "$(dirname "$0")/.." && pwd)
image=${SOFIA_CI_IMAGE:-sofia-sip-ci}

docker build -q -t "$image" -f "$src/ci/Dockerfile" "$src/ci" > /dev/null
mkdir -p "$src/fuzz-out"
docker run --rm -v "$src:/src:ro" -v "$src/fuzz-out:/out" \
  -e BUILD_DIR=/out/build "$image" /src/scripts/fuzz.sh "$@"
