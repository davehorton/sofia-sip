# Build/test environment for sofia-sip, used by scripts/test.sh locally
# (via scripts/docker-test.sh) and by the GitHub Actions test workflow.
FROM ubuntu:24.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential autoconf automake libtool libtool-bin pkg-config \
      clang clang-tools llvm libclang-rt-18-dev \
      check libssl-dev openssl \
      bind9 \
      rsync ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
