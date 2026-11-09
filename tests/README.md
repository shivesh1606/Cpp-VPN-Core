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
| [config/test_ini.cpp](config/test_ini.cpp) | INI syntax: sections, inline comments, `#` inside URLs, CRLF/BOM, line-numbered errors, duplicate keys, overrides |
| [config/test_node_config.cpp](config/test_node_config.cpp) | Defaults equal the pre-M3 constants; file < `--set` precedence; unknown keys; value ranges; auth modes rejected until M4/M5; crypto checked against the registry; `deploy/node.conf.example` stays valid |
| [config/test_cli.cpp](config/test_cli.cpp) | Command-line modes, repeated `--set`, missing values, conflicting modes |
| [crypto/test_node_identity.cpp](crypto/test_node_identity.cpp) | `--gen-key` file: mode 0600, no temporary file left behind, refuses to overwrite unless forced, S_pub = X25519(sk); loading rejects mode 0644, malformed or missing files; base64url |
| [protocol/test_noise.cpp](protocol/test_noise.cpp) | Noise IK byte-identical to the cacophony and snow vectors ([vectors/](protocol/vectors/noise_ik_25519_chachapoly_blake2b.txt)): handshake, handshake hash, transport. HMAC/HKDF-BLAKE2b against Python. Tampering, low-order ephemeral, wrong prologue/key. |
| [protocol/test_v2_wire.cpp](protocol/test_v2_wire.cpp) | v2 sizes (97 B HS_RESP …), byte order, TAI64N ordering, mac1 coverage, strict payload parsing; replay window incl. a 200 000-step reference-model check |
| [protocol/test_v2_engine.cpp](protocol/test_v2_engine.cpp) | `v2::Client` ↔ `v2::Server` in process: handshake + data both ways; **each rejected HS_INIT moves exactly one drop counter and allocates no IP** (design 02 §10.3); retransmit cache; lost ACK → DATA confirms; pending expiry; replay/tamper; inner source check; roaming after auth only; rekey keeps IP + old key decrypts; BYE; keepalive/idle; open mode; cipher preference; keylog |
| [auth/test_ticket.cpp](auth/test_ticket.cpp) | Ticket body pinned byte for byte to design 03 §2; signature over context ‖ body; every §2.1 reason incl. the ±60 s skew; check order; key rotation by `key_id` |
| [auth/test_revocation.cpp](auth/test_revocation.cpp) | Revocation list layout, deterministic encoding, tampering / wrong key / bad count; `RevocationState` refuses equal or older `seq` and keeps the last good list |
| [auth/test_tags_bundle.cpp](auth/test_tags_bundle.cpp) | `tags.conf` parsing and errors; bundle URI round trip and size (224 B / 318 chars), several nodes with DNS names, malformed input |
| [auth/test_issuer_key.cpp](auth/test_issuer_key.cpp) | Issuer key file: 0600, no plaintext key bytes, wrong passphrase, header/salt/box tampering, never overwritten |
| [auth/test_fetcher.cpp](auth/test_fetcher.cpp) | Background fetch: first fetch at once, unchanged bytes not redelivered, errors kept, prompt shutdown; `curlFetch` https-only (and `file://` in tests) |
| [protocol/test_v2_tickets.cpp](protocol/test_v2_tickets.cpp) | `auth.mode = ticket` in process: valid ticket connects; each failure reason moves exactly one counter and allocates no IP; revocation drops the session with BYE and frees the IP; rollback ignored; expired ticket fails at rekey |
| [net/test_cidr.cpp](net/test_cidr.cpp) | `tun_cidr` parsing, netmask, broadcast, pool = server+1 … broadcast−1, prefix limits |
| [net/test_ipv4.cpp](net/test_ipv4.cpp) | `ipv4Destination` (plan H1): short packets, non-IPv4, null |
| [sessions/test_client_manager.cpp](sessions/test_client_manager.cpp) | IP pool, `addClient` with locks, lookups, roaming, BYE removal, sweep. `DISABLED_` test documents defect H3 (enable in M4). |
| [e2e/v1_roundtrip.py](e2e/v1_roundtrip.py) | Real v1 handshake, plus ICMP echo through the tunnel (UDP→TUN and TUN→UDP), plus BYE |
| [e2e/run_docker_e2e.sh](e2e/run_docker_e2e.sh) | Docker: (A) no config, v1 only; (B) `node.conf` + key: v1 **and** v2 (ping, rekey, lost ACK, AES-GCM) with the server configuring `tun0`; (C) no key → refuses to start; (D) client not in `allowed_clients` → no session; (E) `accept_v1 = false` → v1 refused, v2 works; (F) tickets: `vpnctl` bundle connects and rekeys, out-of-scope / missing ticket refused, revoking a connected user drops it (BYE) and reconnects are refused |

## Run

```bash
# Inside Docker (what CI does): build + all unit tests
docker build --target builder -t vpn-builder-stage .

# Local Linux build dir (needs libsodium-dev; libssl-dev for -DWITH_OPENSSL=ON)
cmake -S . -B build -DWITH_OPENSSL=ON && cmake --build build -j && (cd build && ctest --output-on-failure)
./build/tests/unit_tests --gtest_filter='XorBackend.*'      # subset
./build/tests/unit_tests --gtest_also_run_disabled_tests     # include known-defect tests

# End-to-end, all scenarios (needs Docker; from Git Bash or Linux)
bash tests/e2e/run_docker_e2e.sh

# End-to-end by hand (server container with TUN)
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
