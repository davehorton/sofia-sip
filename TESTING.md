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

## nta scenarios (drachtio usage)

`libsofia-sip-ua/nta/check_nta_drachtio.c` (part of `check_nta`) plays SIP exchanges against a scripted peer (`s2check/s2sip`) with the agent set up and driven the way drachtio-server does it: not a UA, a stateless callback that sees every new request, server transactions created later with `nta_incoming_create()`, app-driven 2xx retransmission (`incoming_retransmit_reply()`), app-built ACKs re-sent with `outgoing_retransmit()`, and stateless proxying with `nta_msg_tsend()`. Timers run on virtual time (`s2_fast_forward()`), and DNS answers come from `s2check/s2dns`.

| Case | Scenario |
|------|----------|
| 3.0.x | UAS: late server transaction (UDP, TCP), UAS leg created afterwards, CANCEL before and after the transaction exists, CANCEL after 200, unACKed error response (timer H), 100rel/PRACK, connection closed before the answer |
| 3.1.x | UAC: app-built ACK re-sent on 2xx retransmission, held CANCEL (before any provisional), CANCEL crossing 200, timeout (internal 408), INVITE transaction destroyed before the 2xx, `Contact: *`, Contact rewriting, SRV failover on 503 |
| 3.2.x | Stateless proxy: request forwarded, response back through the stateless callback |

To run one case in an existing build: `libsofia-sip-ua/nta/check_nta drachtio_3_1_0` (shell patterns work, e.g. `'drachtio_3_*'`).

When a drachtio-server bug turns out to be in sofia-sip, add the exchange that triggers it here.

## Transport tests

`libsofia-sip-ua/tport/check_tport.c` tests the stream transports (TCP, TLS, WS, WSS) against a peer that is not sofia-sip: plain non-blocking sockets and OpenSSL, as a phone, browser or carrier would connect. The peer and tport share one thread, and every `su_root_step()` is timed: a step longer than 500 ms fails the test, because a blocked sofia thread stalls all of drachtio-server.

| Case | Scenario |
|------|----------|
| 1.x | Request and response, a request trickled byte by byte, 60 kB requests, pipelined requests split mid-message, CRLF keepalive and pong (including a pong that cannot be written at once over TLS), two requests in one write |
| 2.x | Peer resets before the response, peer closes while the stack holds the transport, `tport_shutdown()` by the stack, many short connections; every connection must be freed |
| 3.x | Plain text to a TLS port, stalled TLS handshake, partial WebSocket frame header, fragmented WebSocket message |
| 4.x | Mutual TLS: a server that requires a client certificate, and the distinct outbound identity (`TPTAG_TLS_CLIENT_CERTIFICATE_FILE`) |

The certificates are in `libsofia-sip-ua/tport/tls/` (CA, server, and a separate client identity); `make-certs.sh` there regenerates them. To run one case: `libsofia-sip-ua/tport/check_tport tport_3_2`.

## Fuzzing

`fuzz/` holds libFuzzer targets for the code that parses input from the network:

| Target | What it fuzzes |
|--------|----------------|
| `sip_msg` | SIP message parsing as tport does it, UDP (one datagram) and TCP/TLS/WS (stream reassembly, pipelining), then what nta and drachtio do with the result (sanity check, encode, dup, URI and Route handling) |
| `url` | URI parsing, printing, comparison (including `tel:`) and parameter lookup |
| `ws` | WebSocket upgrade handshake and frame parsing (`ws.c`) |
| `sres` | DNS response decoding (all record types, name compression) |
| `stun` | the STUN server tport enables by default on UDP ports |

```
scripts/docker-fuzz.sh              # every target for 60 s, in the CI image
scripts/docker-fuzz.sh 600 ws sres  # chosen targets, 10 minutes each
scripts/fuzz.sh 60                  # directly on Linux with clang
```

Each target starts from its seed corpus in `fuzz/corpus/<target>`. New inputs it finds, and crash reproducers, go to the build directory (`fuzz-out/build` with `docker-fuzz.sh`), never into the checkout. A crash fails the run. To replay a reproducer, run the target binary with the crash file as its argument.

When a fuzzer finds a bug, fix it, and add the reproducer to a regression test (or to the target's corpus) so it stays fixed.

## CI

- `.github/workflows/tests.yml` runs `gcc`, `clang` and `asan` on every pull request and on pushes to `main`. It builds the image from `ci/Dockerfile` and calls `scripts/test.sh`, exactly like `scripts/docker-test.sh`.
- `.github/workflows/fuzz.yml` fuzzes each target for 60 s on every pull request and push to `main`, and for 30 minutes nightly. It uploads crash reproducers, and the nightly grown corpus, as artifacts.
- `.github/workflows/clang-analyzer.yml` runs `scan-build`.

## Notes

- **DNS:** `run_test_sresolv` and the DNS half of `run_test_nta` start a private BIND `named`. Without `named` (package `bind9`) they skip those parts.
- **TLS:** the TLS tests use `libsofia-sip-ua/{tport,nta,nth}/agent.pem` (key and certificate) and `cafile.pem` (test CA), valid until 2126.
- **Test vectors:** some RFC 4475 vectors in `libsofia-sip-ua/sip/tests/` need CRLF line endings because their Content-Length counts them. They are marked `-text` in `.gitattributes`.
- **Single suite:** to run one suite in an existing build, use `make -C libsofia-sip-ua/<module> check`, or run its program directly (e.g. `libsofia-sip-ua/nta/run_test_nta`).
