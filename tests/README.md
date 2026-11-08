# Tests

| Kind | Location | Framework | Runs where |
|---|---|---|---|
| Unit | `tests/<module>/test_*.cpp` | GoogleTest, discovered by CTest | Every Docker build (`ctest --output-on-failure`); any Linux build dir |
| End-to-end | `tests/e2e/` | Python 3 scripts against a running `vpn_server` | Manually or in CI with TUN + root (Docker `--cap-add NET_ADMIN`) |

The engine is built as the static library `vpn_core`. Both `vpn_server` and `unit_tests` link it, so tests exercise the real code.

## Layout

| File | Covers |
|---|---|
| [crypto/test_xor_backend.cpp](crypto/test_xor_backend.cpp) | v1 XOR: byte-identical to the removed `XorCipher::crypt` for all 256 keys, round trips, in-place operation, no integrity (documented) |
| [crypto/test_cipher_registry.cpp](crypto/test_cipher_registry.cpp) | Lookup by algorithm and implementation, duplicates, offer order, cross-implementation interop |
| [crypto/test_session_lock_contract.cpp](crypto/test_session_lock_contract.cpp) | **Parameterized over every registered backend.** Round trip with counter and AAD; AEAD tamper rejection (ciphertext, tag, AAD, counter); distinct counters give distinct ciphertext; short input. A newly registered backend is covered automatically. |
| [crypto/test_aead_kat.cpp](crypto/test_aead_kat.cpp) | Known-answer tests (design 01 C5), typed over every implementation: RFC 8439 §2.8.2 for ChaCha20-Poly1305, and GCM spec test cases 13–16 for AES-256-GCM. Seal must match byte for byte; open must recover the plaintext and reject a flipped tag. |
| [crypto/test_aead_lock.cpp](crypto/test_aead_lock.cpp) | `counterNonce` layout (C1). `AeadLock<P>` equals primitive `P` with the counter nonce. Cross-implementation test: every pair of libraries for one algorithm produces identical ciphertext and opens each other's output (runs when built `-DWITH_OPENSSL=ON`, as Docker is). |
| [crypto/hex.h](crypto/hex.h) | Helper: hex vectors pasted in their source document's layout |
| [net/test_ipv4.cpp](net/test_ipv4.cpp) | `ipv4Destination` (plan H1): short packets, non-IPv4, null |
| [sessions/test_client_manager.cpp](sessions/test_client_manager.cpp) | IP pool, `addClient` with locks, lookups, roaming, BYE removal, sweep. `DISABLED_` test documents defect H3 (enable in M4). |
| [e2e/v1_roundtrip.py](e2e/v1_roundtrip.py) | Real v1 handshake, plus ICMP echo through the tunnel (UDP→TUN and TUN→UDP), plus BYE |

## Run

```bash
# Inside Docker (what CI does): build + all unit tests
docker build --target builder -t vpn-builder-stage .

# Local Linux build dir (needs libsodium-dev; libssl-dev for -DWITH_OPENSSL=ON)
cmake -S . -B build -DWITH_OPENSSL=ON && cmake --build build -j && (cd build && ctest --output-on-failure)
./build/tests/unit_tests --gtest_filter='XorBackend.*'      # subset
./build/tests/unit_tests --gtest_also_run_disabled_tests     # include known-defect tests

# End-to-end (server container with TUN)
MSYS_NO_PATHCONV=1 docker run -d --name cppvpn-e2e --cap-add NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun -p 5555:5555/udp vpn-builder-stage /src/build/vpn_server
docker exec cppvpn-e2e sh -c "apt-get update -qq && apt-get install -y -qq iproute2 python3 >/dev/null \
  && ip addr add 10.8.0.1/24 dev tun0 && ip link set tun0 up"
docker exec cppvpn-e2e python3 /src/tests/e2e/v1_roundtrip.py 127.0.0.1 5555 10.8.0.1
docker rm -f cppvpn-e2e
```

## Conventions

- One test file per source unit, mirroring the source tree (`crypto/…` → `tests/crypto/…`).
- Test names are `Suite.WhatItGuarantees`. Known defects are kept as `DISABLED_` tests that reference their plan item.
- Interface contracts (e.g. `SessionLock`) are parameterized tests over all implementations.
- Tests must not depend on network, time of day or execution order. Random data uses fixed seeds.
