# Implementation Plan (through design docs 01–03)

| | |
|---|---|
| **Status** | Active. Created 2026-11-08. |
| **Covers** | [01 Cipher layer](../design/01-cipher-layer.md), [02 Handshake](../design/02-handshake.md), [03 Tickets](../design/03-tickets.md), and the node-config part of 04 (§ Discussion 4a) |
| **Not covered** | Topics deferred to [parked-discussions.md](parked-discussions.md) |
| **Experiments** | [experiments/](../../experiments/README.md) |

## Principles

- **One milestone, one branch, one PR to `master`.** Each milestone ends in a deployable state: the server builds in Docker, and the existing Android app keeps working until M6/M7.
- **Wire compatibility:** v1 stays supported until M7. v2 packets start with `ver = 0x20`, so one binary can demultiplex both (design 02 §3).
- **Test on Windows first:** every protocol change lands in the Windows test client before Android. The C++ protocol code is shared between server and Windows client.
- **Tests:** every milestone ships **GoogleTest** unit tests under [`tests/`](../../tests/README.md), run by CTest inside the Docker build (a failing test fails the build). Crypto and Noise also use published test vectors (design 01 C5, design 02 §10). Paths that need TUN/root get an end-to-end script under `tests/e2e/`.
- **Measure:** milestones that touch the hot path re-run or extend an experiment.

## Milestone overview

```
M0 Windows test client (v1) ──┐
M1 Cipher-layer refactor ─────┼──▶ M2 libsodium + bench ──┐
                              │                           ├──▶ M4 Protocol v2 (server + Windows) ──▶ M5 Tickets ──▶ M6 Android v2 ──▶ M7 Retire v1
M3 Node config & identity ────┴───────────────────────────┘
```

| # | Milestone | Status | Depends on |
|---|---|---|---|
| M0 | Windows test client (protocol v1) | **Done** (branch `feature/windows-test-client`) | — |
| M1 | Cipher-layer refactor, no wire change, plus hardening fixes H1–H2 | **In review** (branch `feature/m1-cipher-layer`) | — |
| M2 | libsodium backend, KATs, `crypto_bench`, experiment 002 | **In review** (branch `feature/m2-libsodium`); experiment 002 target-node runs deferred (2026-11-08) | M1 |
| M3 | Node config file and node identity key | **In review** (branch `feature/m3-node-config`) | — |
| M4 | Protocol v2: Noise IK, v2 transport, session table; server + Windows client | **In review** (branch `feature/m4-protocol-v2`); experiments 003/004 deferred | M2, M3 |
| M5 | Tickets: verifier, revocation, `vpnctl`, bundle import (Windows) | Not started | M4 |
| M6 | Android: v2 + tickets + QR import | Not started | M5 |
| M7 | Retire v1; docs and README refresh | Not started | M6 |

---

## M0 — Windows test client (protocol v1): done

Revived the client from local branch `adding_windows_cpp_client` (commit `25cc800`, never pushed). Only the sources were taken; committed `.exe` files and `.claude/` settings were left behind.

- **Location:** `clients/windows/`: [README](../../clients/windows/README.md), `main.cpp`, `build.ps1`, `vpn_client.conf.example`, Wintun 0.14.1 (signature verified).
- **Changes from that branch:**
  - `--probe` mode (no admin, no adapter);
  - admin check;
  - receive timeout disabled by default (the v1 server sends nothing to idle clients);
  - keepalive 15 s;
  - handshake timing;
  - MinGW static build;
  - warnings fixed.
- **Verified 2026-11-08:** probe against the real `vpn_server` in Docker. HELLO→WELCOME took 1.76 ms, then ACK, 3 × KEEPALIVE and BYE; the server logged `[BYE] Removing client session 1000`.
- **Not verified:** tunnel mode, which needs an elevated terminal (recipe in the client README).

## M1 — Cipher-layer refactor (no wire change)

Design 01 §2.2, §4, rollout step 1.

| Task | Files |
|---|---|
| `SessionLock`, `CipherBackend`, `CipherRegistry` interfaces | new `crypto/SessionLock.h`, `crypto/CipherRegistry.{h,cpp}` |
| `XorBackend` (id 0) wrapping today's XOR; v1 key byte expands to a 32-byte key | `crypto/backends/XorBackend.{h,cpp}`; remove `XorCipher` singleton |
| Client state: `uint8_t xor_key` → `std::unique_ptr<SessionLock> rx, tx` | [sessions/client/Client_Manager.h:24](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/sessions/client/Client_Manager.h#L24), `addClient` |
| Call sites → `open()`/`seal()` | [main.cpp:75](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/main.cpp#L75), [main.cpp:449](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/main.cpp#L449) |
| **H1:** TUN read: require `n ≥ 20` before reading the IPv4 destination | [main.cpp:434-436](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/main.cpp#L434-L436) |
| **H2:** detect truncated datagrams (`MSG_TRUNC` in `msg_flags`) and count them as drops | [main.cpp:366-377](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/main.cpp#L366-L377) |
| Test scaffold: `tests/` + CTest; XOR backend round-trip test | `CMakeLists.txt`, `tests/` |

**Acceptance**
- Docker build is green.
- The Windows probe and tunnel work, and the Android app works unchanged (same wire bytes).
- `enc_cyc_per_pkt` stays within ±5% of before (the virtual call is negligible).

**Delivered (2026-11-08)**
- **New code:**
  - `crypto/SessionLock.h` (`SessionLock`, `CipherBackend`, `CipherId`);
  - `crypto/CipherRegistry.{h,cpp}`;
  - `crypto/backends/XorBackend.{h,cpp}`;
  - `net/ip/Ipv4.h`.
- **Removed:** `crypto/XorCipher.{h,cpp}`.
- **`Client` and `addClient`:** `Client` holds `rx`/`tx` locks and `tx_counter`; `addClient` takes ownership of both locks and rejects null locks or out-of-pool IPs.
- **H1:** TUN packets are routed only if `ipv4Destination` succeeds (length ≥ 20 and version 4).
- **H2:** `MSG_TRUNC` datagrams are dropped (new `udp_rx_truncated` counter).
- **Bounds check (found during M1):** each send slot is checked to hold header + payload + tag before encrypting. The TUN read buffer (2000 B) and send slot (2000 B) previously allowed a 5-byte overflow for payloads over 1995 B.
- **Decrypt order:** the RX size check now runs before decryption. Failed `open()` increments the new `rx_auth_fail` counter.
- **Build:** CMake builds `vpn_core` (static library) linked by `vpn_server` and `unit_tests`. The Dockerfile installs `libgtest-dev` and runs `ctest`.
- **Tests:** 35 GoogleTest cases ([tests/README.md](../../tests/README.md)), including a contract suite parameterized over all registered backends. The e2e script is [tests/e2e/v1_roundtrip.py](../../tests/e2e/v1_roundtrip.py).
- **Not measured:** the `enc_cyc_per_pkt` ±5% check needs sustained traffic on a profiling build. It's deferred to experiment 003.

## M2 — libsodium backend, KATs, benchmark

Design 01 §2.1, C5, §5; rollout step 2.

| Task | Notes |
|---|---|
| libsodium (required, no switch) in CMake; static `libsodium.a` | [Dockerfile:3-7](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/Dockerfile#L3-L7): add `libsodium-dev` |
| `SodiumChaCha20Poly1305` backend (id 1), plus `SodiumAes256Gcm` (id 2, runtime-gated by `crypto_aead_aes256gcm_is_available()`) | design 01 §2.1 |
| KAT tests: RFC 8439 §2.8.2; NIST GCM vectors; cross-backend seal/open | design 01 C5 |
| `crypto_bench` target, grown from [experiments/001/pkt_bench.c](../../experiments/001-crypto-per-packet-cost/pkt_bench.c), iterating the registry | design 01 §5 |
| Optional: `WITH_OPENSSL` backends | for experiment 002 comparisons |
| **Experiment 002:** `crypto_bench` on the GCP node (and Oracle A1 arm64 if available) | arm64 build needed for A1 |

**Acceptance:** KATs pass; `crypto_bench` prints every registered backend; experiment 002 results are committed.

**Delivered (2026-11-08)**
- **Backends:** one generic `AeadLock<P>`/`AeadBackend<P>` ([crypto/backends/AeadLock.h](../../crypto/backends/AeadLock.h)) holds the counter nonce (C1) and tag handling. The primitives:
  - libsodium ChaCha20-Poly1305 (id 1, always) and AES-256-GCM (id 2, only if `crypto_aead_aes256gcm_is_available()`), in [SodiumAead](../../crypto/backends/SodiumAead.h);
  - OpenSSL ChaCha20-Poly1305 and AES-256-GCM behind `-DWITH_OPENSSL=ON`, in [OpenSslAead](../../crypto/backends/OpenSslAead.h).
- **Registry order** (= default implementation and offer order): chacha20poly1305 (libsodium, openssl), aes256gcm (libsodium, openssl), xor. The server logs every registered backend at startup.
- **Build:** libsodium required, linked statically. OpenSSL optional, statically linked `libcrypto.a`. The Docker build installs `libsodium-dev` and `libssl-dev` and builds `-DWITH_OPENSSL=ON`, so the cross-implementation test runs in CI.
- **Tests:** 74 GoogleTest cases with OpenSSL, 58 without:
  - KATs: RFC 8439 §2.8.2; GCM spec test cases 13–16;
  - `counterNonce` layout;
  - `AeadLock<P>` equals `P` with the counter nonce;
  - cross-implementation, byte-identical;
  - registry composition;
  - contract suite over all backends. Test names are now stable (no pointer values).
- **`crypto_bench`:** [tools/crypto_bench.cpp](../../tools/crypto_bench.cpp). Times seal / open / open-forged of every registered backend through the real `SessionLock`.
- **Experiment 002:** [results](../../experiments/002-crypto-bench-backends/README.md) on the dev laptop. Two findings changed code or docs:
  - **Release builds are `-O3`:** CMake appends `-O3` to the project's `-O2`, so the Docker image's XOR is vectorized. Experiment 001's `-O2` XOR baseline matches `scripts/runbuild.sh` builds, not the Docker image.
  - **Dirty upper vector state:** after OpenSSL's AVX code, libsodium's AES-NI code ran 1.7× slower. Fixed in the engine: the OpenSSL backend issues `vzeroupper` after each call ([VectorState.h](../../crypto/backends/VectorState.h)).
- **Not done:**
  - **GCP e2-micro and Oracle A1 runs:** deferred by decision (2026-11-08). The run recipe is in the experiment README.
  - **arm64 performance:** no numbers yet. Correctness was checked under QEMU emulation: Ubuntu 24.04 arm64, libsodium 1.0.18, OpenSSL 3.0.13, 69/69 tests pass. libsodium AES-256-GCM is correctly not registered; OpenSSL AES-256-GCM passes the KATs and the cross-implementation test. Ubuntu 22.04 arm64 could not be checked: its `ldconfig` crashes under Docker Desktop's QEMU while apt installs, before any of our code runs.

## M3 — Node config file and node identity

Decisions N1–N5 below (Discussion 4a). Design 01 §2.3, design 02 §7, design 03 §8.

| Task | Notes |
|---|---|
| INI parser plus `NodeConfig` struct; `--config PATH` (default `/etc/cppvpn/node.conf`) | replaces hardcoded port, pool and timeouts at [main.cpp:256-267](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/main.cpp#L256-L267) |
| `vpn_server --gen-key PATH`: writes the X25519 private key (mode 0600) and prints `S_pub` (base64url) | N1 |
| On start: load the key and refuse to run if it's missing | N1 |
| Server assigns the `tun0` address from `tun_cidr`; pool derived from it | N5 |
| Example `deploy/node.conf.example` | all keys documented |

**Acceptance:** with no `--config`, the server behaves exactly like today; with a config, port, pool and keys come from the file.

**Delivered (2026-11-09)**
- **Config:**
  - [config/Ini](../../config/Ini.h): INI parser with line-numbered errors and duplicate-key detection;
  - [config/NodeConfig](../../config/NodeConfig.h): schema, defaults and validation;
  - [config/Cli](../../config/Cli.h): command line.
- **Precedence (N3):** defaults < file < `--set section.key=value`. `/etc/cppvpn/node.conf` is read automatically if it exists; `--config PATH` overrides it.
- **Defaults equal the pre-M3 constants:** port 5555, `tun0`, pool 10.8.0.2 × 100, pending 10 s, idle sweep 60 s. A unit test pins them.
- **Strict validation:**
  - unknown sections or keys are errors;
  - `crypto.*` is checked against the cipher registry;
  - `xor` needs `allow_insecure_xor`;
  - `auth.mode` other than `open` is **rejected until M4/M5**, so a config can't claim protection the binary doesn't have;
  - keys for protocol v2 and tickets are validated now, with a "not used until M4/M5" warning.
- **Identity (N1):**
  - `--gen-key PATH [--force]` writes the X25519 private key as base64url, mode 0600, via a temporary file and rename, and refuses to overwrite without `--force`;
  - `--pubkey PATH` prints S_pub;
  - with a config file, the server refuses to start without the key, or if the key is readable by group or others ([crypto/NodeIdentity](../../crypto/NodeIdentity.h)).
- **TUN (N5):** with `tun_cidr`, `TunDevice::configure` sets address, netmask and MTU and brings the link up (ioctl), and the pool becomes server+1 … broadcast−1. Without `tun_cidr`, `tun0` is configured externally as before.
- **CLI:** also `--check-config` (validate, print the effective config and S_pub), `--version`, `--help`.
- **Reference config:** [deploy/node.conf.example](../../deploy/node.conf.example), every key documented. A unit test keeps it valid.
- **`.gitignore`:** now excludes `*.key`, `*.pem`, `.env` and Terraform state.
- **Tests:**
  - 110 GoogleTest cases with OpenSSL, 94 without; 45 new (INI, CIDR, CLI, NodeConfig, NodeIdentity, base64url);
  - e2e [tests/e2e/run_docker_e2e.sh](../../tests/e2e/run_docker_e2e.sh): (A) no config, pre-M3 behaviour; (B) config + key, server configures `tun0`; (C) config without a key refuses to start. All pass, each with the v1 round trip.

## M4 — Protocol v2 (server + Windows client)

Design 02 in full; design 01 rollout step 3.

| Task | Notes |
|---|---|
| `protocol/noise/{SymmetricState,HandshakeState}`: Noise IK, BLAKE2b, HMAC/HKDF per Noise §4.3 | design 02 §2 |
| Noise test-vector test (`Noise_IK_25519_ChaChaPoly_BLAKE2b`) | design 02 §10.1 |
| v2 wire structs and the `ver` demux (keep v1 alongside) | design 02 §3 |
| `HandshakeTable` (PENDING, msg2 cache), session indexes `receiver_idx` / `s_c` / `tun_ip`, random IDs | design 02 §6; supersedes `ClientSession` and the sequential `generateSessionId` |
| Responder pipeline in cheapest-first order; IP allocated only after authentication | design 02 §5 |
| Transport: v2 header as AAD, explicit counter, replay window, roaming only after `open()` succeeds | design 01 C1/C2/C6 |
| Explicit encrypted ACK plus DATA fallback; drop-reason counters; `ENABLE_KEYLOG` (debug builds) | design 02 D3, §8 |
| Bidirectional KEEPALIVE; rekey 120 s, reject after 180 s | design 02 §7 |
| `auth_mode = open | allowlist` | design 02 §7 |
| Windows client v2 using the shared C++ protocol code. libsodium for MinGW: `pacman -S mingw-w64-x86_64-libsodium` | M0 client gains `--protocol v2` |
| **Experiments 003, 004** (end-to-end throughput/latency v1 vs v2; HELLO flood vs mac1) | [experiments/](../../experiments/README.md) |

Superseded review findings:
- **H3:** a sweep erasing the new client's UDP mapping is gone, because `ip:port` is no longer a key.
- **H4:** IP reserved before authentication is fixed.
- **H5:** spoofable roaming, BYE and KEEPALIVE are fixed.
- **H6:** a lost ACK no longer strands the client.
- **H7:** `DiffieHellman.h` (ODR, globals in a header) is removed. *(Update: kept until M7, because protocol v1 still uses it. H3 also remains for v1 clients, and its `DISABLED_` test stays until M7.)*

**Acceptance**
- The Windows client completes v2 against the Docker server.
- Every negative test from design 02 §10.3 increments exactly one drop counter.
- A v1 Android client still connects to the same binary.

**Delivered (2026-11-09)**
- **Noise:** [protocol/noise/Noise.h](../../protocol/noise/Noise.h) implements `Noise_IK_25519_ChaChaPoly_BLAKE2b` on libsodium (HMAC/HKDF over BLAKE2b, `CipherState`, `SymmetricState`, `HandshakeIK`). It is byte-identical to **two** published vector sets, cacophony and snow ([vector file](../../tests/protocol/vectors/noise_ik_25519_chachapoly_blake2b.txt)).
- **Wire:** [protocol/v2/Wire.h](../../protocol/v2/Wire.h) implements the §3 layouts, mac1, TAI64N and the payloads. [ReplayWindow.h](../../protocol/v2/ReplayWindow.h) is RFC 6479.
- **Server:** [protocol/v2/Server.h](../../protocol/v2/Server.h) is a socket-free responder:
  - the §5 pipeline, with IP allocation only at step 8;
  - a msg2 cache for retransmits;
  - an ACK, or the first DATA/KEEPALIVE as fallback, confirms a session;
  - rekey keeps the IP and keeps the previous key for receiving;
  - roaming happens only after `open()`;
  - the inner source IP must be the client's own (anti-spoofing, added);
  - BYE, pending expiry, reject-after, idle removal and server keepalives;
  - a drop-reason counter for every failure, plus the `ENABLE_KEYLOG` hook.
- **Client:** [protocol/v2/Client.h](../../protocol/v2/Client.h) is the initiator, shared by the Linux [tools/vpn_client_v2.cpp](../../tools/vpn_client_v2.cpp) and the Windows client.
- **`main.cpp`:**
  - the first byte demultiplexes v1 and v2 on one port and one `tun0`;
  - v2 sealing shares the `sendmmsg` batch;
  - a 1 s tick runs v2 timers and keepalives;
  - a v2 stats line is logged.

  v2 runs whenever the node has a key, which means a config file is in use.
- **Config:**
  - `auth.mode = allowlist` with an `allowed_clients` file (default), `open` only with `-DALLOW_OPEN_AUTH=ON`, `ticket` rejected until M5;
  - `[crypto]` and the timer keys are live;
  - new keys `node.accept_v1` and `timers.keepalive_s`;
  - new CMake options `ALLOW_OPEN_AUTH` and `ENABLE_KEYLOG`.
- **Windows client:** `--protocol v2 --server-pub … --key …`, `--gen-key` and `--pubkey` ([ProtocolV2.inc](../../clients/windows/ProtocolV2.inc)). Probe and tunnel modes both support rekey and keepalive. Built with MinGW and static libsodium 1.0.20.
- **Tests:**
  - 148 GoogleTest cases with OpenSSL, 132 without. 37 are new: Noise vectors, HMAC/HKDF, wire, replay window, and 18 in-process client↔server cases. Each §10.3 negative case increments exactly one counter and allocates no IP.
  - e2e [run_docker_e2e.sh](../../tests/e2e/run_docker_e2e.sh): v1 with and without a config; v2 ping, rekey, lost ACK and AES-GCM; a client not on the allowlist; `accept_v1 = false`. All pass.
- **Windows ↔ Docker server:**
  - v2 probe: handshake in 3.2 ms; 2 rekeys (new hsid, same IP); keepalives 2 sent and 2 received; BYE.
  - v1 probe against the same server: OK.
- **Not done:**
  - Windows tunnel mode, which needs an elevated terminal (as in M0).
  - The Android v1 app, which the e2e v1 checks cover (same wire format).
  - Experiments 003 and 004 (deferred, like the other benchmarks).
  - mac2 cookies (P3).

## M5 — Tickets

Design 03.

| Task | Notes |
|---|---|
| `auth/Ticket` (encode/verify, shared with `vpnctl`) | design 03 §2 |
| `auth/RevocationList` plus fetcher, run off the packet loop | design 03 §6 |
| `tools/vpnctl`: `init`, `node add`, `issue`, `revoke`; passphrase-encrypted issuer key | design 03 §4–5 |
| `auth_mode = ticket`; re-check the ticket on rekey; drop revoked sessions on list update | design 03 §2.2 |
| Windows client: `--bundle FILE|STRING` | design 03 §5 |

**Acceptance**
- `vpnctl issue` → bundle → the Windows client connects.
- Each verification failure maps to its own counter.
- A revoked user is dropped within one poll interval.

## M6 — Android v2 + tickets

| Task | Notes |
|---|---|
| Kotlin Noise IK initiator on Lazysodium; same test vectors as the C++ side | design 02 §10 |
| `SessionLock` interface (Kotlin), ChaCha20-Poly1305 default | design 01 §4 |
| QR / `cppvpn://` bundle import; Keystore-wrapped `device_sk` | design 03 §5 |
| VpnService MTU 1420 | design 01 §3 |
| Remove the typed-IP flow (keep it as a developer option) | — |

## M7 — Retire v1

- Remove the v1 demux, the `XorBackend` default and `PKT_*` v1 structs.
- Keep `xor-insecure` for benchmarks only.
- Update the README feature and security sections, and mark design docs 01–03 as Implemented.

---

## Discussion 4a: node config and identity (correlated with M3/M4)

**Status: Accepted (2026-11-08)**, all recommendations as listed. The parts of design 04 that M3–M5 need. The rest of 04 is parked (P1).

| ID | Question | Recommendation | Alternatives |
|---|---|---|---|
| N1 | How the node's static key is created | Explicit `vpn_server --gen-key`; the server refuses to start without a key file | Auto-generate on first start: after a disk loss the key changes silently and every issued bundle breaks. Generating in `vpnctl` means the private key has to travel to the node. |
| N2 | Config format | INI `key = value` with sections, a ~100-line parser, no dependency. Same style as the Windows client config. | TOML/JSON library (extra dependency) |
| N3 | Location and precedence | `/etc/cppvpn/node.conf`, `--config` override; defaults < file < CLI; secrets in separate files referenced by path (`node_key = /etc/cppvpn/node.key`, mode 0600) | Environment variables |
| N4 | Config reload | Restart only for now. Clients re-handshake in about 5 s. The revocation list hot-reloads independently through its fetcher. | `SIGHUP` live reload (parked P9) |
| N5 | Who configures `tun0` | The server sets the address/netmask and brings the link up via `ioctl` from `tun_cidr = 10.8.0.1/24`, and derives the pool from it. NAT (MASQUERADE) stays in deployment (P1). | Keep it external, as today (address set by deploy scripts outside this repo; pool hardcoded separately at [main.cpp:256](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/main.cpp#L256), so the two can mismatch) |

Proposed `node.conf`:

```ini
[node]
id          = in-1
tags        = friends, region-in          ; design 03 §3
port        = 5555
node_key    = /etc/cppvpn/node.key         ; vpn_server --gen-key

[tunnel]
tun_name    = tun0
tun_cidr    = 10.8.0.1/24                  ; pool = .2 .. .254
mtu         = 1420

[crypto]                                   ; design 01 §2.3
algorithms            = chacha20poly1305, aes256gcm
impl.chacha20poly1305 = libsodium
impl.aes256gcm        = libsodium
allow_insecure_xor    = false

[auth]                                     ; design 02 §7, design 03
mode           = allowlist                 ; open | allowlist | ticket
allowed_clients = /etc/cppvpn/allowed_clients
issuer_pk.1    = <base64url>
revocation_url = https://raw.githubusercontent.com/<owner>/<repo>/main/revocations.bin

[timers]                                   ; design 02 §7
pending_expiry_s = 10
rekey_after_s    = 120
reject_after_s   = 180
```
