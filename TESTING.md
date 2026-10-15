# Testing sofia-sip

## Quick start

With Docker (any host, including macOS). This is the same environment CI uses:

```
scripts/docker-test.sh              # gcc, clang and asan in turn
scripts/docker-test.sh asan         # one mode
```

On Linux with the dependencies from `ci/Dockerfile` installed:

```
scripts/test.sh gcc
```

`scripts/test.sh` copies the tree to `/tmp/sofia-build-<mode>` (override with
`BUILD_DIR`), then bootstraps, configures, builds and runs `make check`. It
never modifies the checkout.

## Modes

| Mode      | What it runs |
|-----------|--------------|
| `gcc`     | gcc `-O2 -Wall` build, gating suites |
| `clang`   | clang `-O2 -Wall` build, gating suites |
| `asan`    | clang with AddressSanitizer and UndefinedBehaviorSanitizer, gating suites; any report fails the run |
| `all-gcc` | gcc build, every module's tests, including the modules drachtio does not use (informational) |

The gating suites are the modules drachtio-server uses: `su bnf ipt url msg sip sresolv tport nta`.
`nua`, `soa`, `nea`, `nth`, `http`, `iptsec`, `sdp` and `stun` still build, and `all-gcc` runs their tests, but they don't gate.

## CI

`.github/workflows/tests.yml` runs `gcc`, `clang` and `asan` on every pull request and on pushes to `main`. It builds the image from `ci/Dockerfile` and calls `scripts/test.sh`, exactly like `scripts/docker-test.sh`. `.github/workflows/clang-analyzer.yml` runs `scan-build` separately.

## Notes

- **DNS:** `run_test_sresolv` and the DNS half of `run_test_nta` start a private BIND `named`. Without `named` (package `bind9`) they skip those parts.
- **TLS:** the TLS tests use `libsofia-sip-ua/{tport,nta,nth}/agent.pem` (key and certificate) and `cafile.pem` (test CA), valid until 2126.
- **Test vectors:** some RFC 4475 vectors in `libsofia-sip-ua/sip/tests/` need CRLF line endings because their Content-Length counts them. They are marked `-text` in `.gitattributes`.
- **Single suite:** to run one suite in an existing build, use `make -C libsofia-sip-ua/<module> check`, or run its program directly (e.g. `libsofia-sip-ua/nta/run_test_nta`).
