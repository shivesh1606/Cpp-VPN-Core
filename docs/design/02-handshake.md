# 02 — Handshake (Protocol v2)

| | |
|---|---|
| **Status** | Accepted (2026-11-08). **Implemented in M4** (server, Linux test client, Windows client); tickets (`auth_mode = ticket`) follow in M5. See §11. |
| **Scope** | Authenticated key exchange between client and node; session lifecycle; transport header |
| **Produces** | `k_c2s`, `k_s2c`, consumed by [01 — Cipher layer](01-cipher-layer.md) (`CipherBackend::newLock`) |
| **Consumes** | Access ticket from [03 — Tickets](README.md#index) (opaque here, via `TicketVerifier`) |
| **Replaces** | Toy DH ([crypto/DiffieHellman.h](../../crypto/DiffieHellman.h)), `PKT_HELLO`/`PKT_WELCOME`/`PKT_CLIENT_ACK` ([protocol/Handshake.h](../../protocol/Handshake.h)), the pending-session table keyed by address ([sessions/session/ClientSession.h](../../sessions/session/ClientSession.h)) |

## Decisions

| ID | Decision | Rationale |
|---|---|---|
| D1 | Implement **Noise IK** ourselves on libsodium primitives. Suite: `Noise_IK_25519_ChaChaPoly_BLAKE2b` | One crypto dependency (libsodium on the server, Lazysodium on Android). libsodium provides BLAKE2b but not BLAKE2s. Correctness is gated by the official Noise test vectors. |
| D2 | Reserve a 16-byte `mac2` field now (zero-filled); implement the cookie mechanism later | Wire format stays stable when the cookie DoS defence is added |
| D3 | Keep an **explicit, encrypted `ACK`** (key confirmation). The first authenticated DATA/KEEPALIVE also confirms as a fallback. | Easier debugging: a distinct, logged confirmation event carrying a handshake ID that both sides log. The fallback means a lost ACK doesn't strand a client that believes it's connected. |
| D4 | Packet `type` is sent in the clear and authenticated as AAD | Visible in tcpdump/Wireshark for debugging; any change to it fails AEAD verification. Trade-off: an observer can tell DATA from KEEPALIVE. |

Not WireGuard wire-compatible (different hash, no PSK, different header). That's intended.

## 1. Security goals

| # | Property | Mechanism |
|---|---|---|
| G1 | Server authentication (no MITM) | Client knows `S_pub` before connecting (bundle / node registry); `es` and `se` DH |
| G2 | Client authentication bound to the ticket | `ss` DH; `TicketVerifier` checks `ticket.device_pk == s_c` |
| G3 | Forward secrecy | `ee` DH with per-handshake ephemerals |
| G4 | Client identity hiding | `s_c` encrypted under the `es`-derived key; ticket inside the encrypted payload |
| G5 | 1-RTT to the first data packet | msg1/msg2; ACK sent together with the first data |
| G6 | Replay resistance | TAI64N timestamp, strictly increasing per `s_c` |
| G7 | No state or IP allocation before authentication | Processing order in §5 (fixes the pool-exhaustion bug at [main.cpp:162](../../main.cpp#L162)) |
| G8 | Idempotent retransmission (keeps the PR #2 / `fa857d9` behaviour) | msg2 cache keyed by `hash(msg1)` |
| G9 | No reflection amplification | msg2 (97 B) < msg1 (≈290 B) |
| G10 | Unauthenticated scanners get no response | `mac1` keyed by `S_pub` |

## 2. Noise pattern and key schedule

```
Noise_IK_25519_ChaChaPoly_BLAKE2b
  <- s
  ...
  -> e, es, s, ss          msg1 (HELLO)
  <- e, ee, se             msg2 (WELCOME)
```

```
InitializeSymmetric("Noise_IK_25519_ChaChaPoly_BLAKE2b")  → h = name ‖ zero-pad to 64 B, ck = h
MixHash(prologue = "cppvpn-v2")
MixHash(S_pub)                                             pre-message s
msg1:  MixHash(e_c)
       MixKey(DH(e_c, S))   → encrypt s_c        (es)   G1, G4
       MixKey(DH(s_c, S))   → encrypt payload1   (ss)   G2
msg2:  MixHash(e_s)
       MixKey(DH(e_s, e_c))                      (ee)   G3
       MixKey(DH(e_s, s_c)) → encrypt payload2   (se)   G1, G3
Split(ck) → (k_c2s, k_s2c), each truncated to 32 B (Noise §5.2, HASHLEN = 64)
handshake_id = h[0:8]  (final handshake hash, logged by both sides)
```

Primitive mapping (libsodium):

| Noise function | Implementation |
|---|---|
| `DH` | `crypto_scalarmult` (X25519). A non-zero return (all-zero output from a low-order point) aborts the handshake. |
| `HASH` | `crypto_generichash`, 64-byte output (BLAKE2b-512) |
| `HMAC-HASH` | HMAC (RFC 2104, block size 128) built on `crypto_generichash`. Keyed BLAKE2 is **not** a substitute (Noise §4.3). |
| `HKDF` | Noise §4.3 construction over `HMAC-HASH` |
| `ENCRYPT`/`DECRYPT` | `crypto_aead_chacha20poly1305_ietf_*`, nonce = 32 zero bits ‖ 64-bit LE `n` (Noise §12.3) |

Transport keys from `Split()` aren't used with Noise's implicit nonces. They're handed to doc 01 locks, which use the explicit 64-bit counter carried in each transport header (needed over UDP; same approach as WireGuard).

## 3. Wire format

All v2 packets start with `ver = 0x20`. It can't collide with the legacy v1 first byte (type values 1–6), so one binary can demultiplex v1 and v2 during migration.

### 3.1 Packet types

| type | Name | Direction | Encrypted under |
|---|---|---|---|
| 1 | `HS_INIT` (msg1) | C→S | handshake keys |
| 2 | `HS_RESP` (msg2) | S→C | handshake keys |
| 3 | `ACK` | C→S | `k_c2s`, counter 0 |
| 4 | `DATA` | both | `k_c2s` / `k_s2c` |
| 5 | `BYE` | both | transport key |
| 6 | `KEEPALIVE` | both | transport key, empty payload |
| 7 | `COOKIE_REPLY` | S→C | reserved (D2) |

### 3.2 Layouts

```
HS_INIT (msg1) ≈ 290 B
┌─────┬──────┬────────────┬──────────┬────────────┬───────────────────────────────────────────────┬──────┬──────┐
│ ver │ type │ sender_idx │ e_c      │ AEAD(s_c)  │ AEAD( ts TAI64N 12 ‖ offer_n u8 ‖ offer[] ‖   │ mac1 │ mac2 │
│ u8  │ =1   │ u32 random │ 32       │ 32 + 16    │       ticket_len u16 ‖ ticket (136, doc 03) ) │ 16   │ 16   │
│     │      │            │          │            │ + 16                                          │      │ =0   │
└─────┴──────┴────────────┴──────────┴────────────┴───────────────────────────────────────────────┴──────┴──────┘

HS_RESP (msg2) = 97 B
┌─────┬──────┬────────────┬──────────────┬──────────┬───────────────────────────────────────────────┬──────┬──────┐
│ ver │ type │ sender_idx │ receiver_idx │ e_s      │ AEAD( tun_ip u32 ‖ cipher_id u8 ‖             │ mac1 │ mac2 │
│ u8  │ =2   │ u32 random │ = client idx │ 32       │       keepalive_s u16 ) + 16                  │ 16   │ =0   │
└─────┴──────┴────────────┴──────────────┴──────────┴───────────────────────────────────────────────┴──────┴──────┘

Transport header (ACK / DATA / BYE / KEEPALIVE), 14 B, used as AAD (doc 01 C2)
┌─────┬──────┬──────────────┬────────────────┬──────────────────────┬─────────┐
│ ver │ type │ receiver_idx │ counter u64 LE │ ciphertext           │ tag 16  │
└─────┴──────┴──────────────┴────────────────┴──────────────────────┴─────────┘
ACK payload = handshake_id (8 B) → 38 B total.  DATA counters start at 1.
```

### 3.3 mac1 / mac2

```
mac1_key = BLAKE2b-256("mac1----" ‖ S_pub)
mac1     = BLAKE2b-128(key = mac1_key, msg[0 : offset(mac1)])
mac2     = 16 zero bytes (reserved; cookie mechanism is future work)
```

For msg2, `mac1` is keyed with the client's static public key, as in WireGuard.

## 4. Client (initiator) flow

```
Client                                                              Node
  │ build msg1 (fresh e_c, TAI64N now)                                │
  │── HS_INIT ───────────────────────────────────────────────────────▶│  §5
  │      no HS_RESP within 5 s (+ jitter) → new msg1 (new e_c, new ts)│
  │◀────────────────────────────────────────────────────── HS_RESP ───│
  │ verify, Split → k_c2s/k_s2c, newLock(cipher_id)                   │
  │── ACK {handshake_id} (ctr 0) ────────────────────────────────────▶│  PENDING → ACTIVE  (log "confirm=ack")
  │══ DATA (ctr 1..) ════════════════════════════════════════════════▶│  if ACK was lost: first valid DATA
  │                                                                   │  confirms (log "confirm=data", stat++)
```

## 5. Node (responder) processing order

Checks run cheapest first. Each failure maps to a drop-reason counter (§8).

```
recv HS_INIT
  1. size, ver ........................................ ✗ HS_DROP_FORMAT
  2. mac1 ............................................. ✗ HS_DROP_MAC1        (silent)
  3. msg2 cache hit for hash(msg1) .................... ✓ resend cached HS_RESP; no new state     (G8)
  4. DH es → open s_c; DH ss → open payload ........... ✗ HS_DROP_DECRYPT
  5. auth (by auth_mode, §7): TicketVerifier / allowlist  ✗ HS_DROP_AUTH_<reason>
  6. ts > last_ts[s_c] ................................ ✗ HS_DROP_REPLAY
  7. cipher negotiation (doc 01 §2.3) ................. ✗ HS_DROP_NO_CIPHER
  8. IpPool.alloc() ................................... ✗ HS_DROP_POOL_EMPTY   ← first allocation happens here
  9. sender_idx_s = randombytes_uniform/u32 (unique); build msg2; Split; newLock ×2
 10. store PENDING{created, keys, ip, s_c, handshake_id}; cache msg2; last_ts[s_c] = ts
```

`last_ts` lives in memory and is lost on restart. Within a ticket's validity, a captured msg1 can then be replayed once after a node restart. It can only create a PENDING entry that expires in 10 s, because the attacker can't complete the ACK without `e_c`.

## 6. Session state machine

```
             valid HS_INIT                     ACK ok  |  first DATA/KEEPALIVE ok (fallback)
  (none) ─────────────────▶ PENDING ──────────────────────────────────────────────▶ ACTIVE
                              │ identical msg1 → resend cached msg2                    │
                              │ newer ts, same s_c → replace; free old IP              │ rekey: HS_INIT, newer ts
                              └ 10 s unconfirmed → expire; free IP                     ▼
                                                                  ACTIVE(current) + PENDING(next)
                                                                  next confirmed → swap keys; old rx key
                                                                  kept for a short grace period (late packets)
  ACTIVE ── BYE (authenticated) │ 180 s without an authenticated packet ──▶ REMOVED; free IP
```

- Indexes: `receiver_idx → Session` (hot path); `s_c → Session` (replace/rekey); `tun_ip → Session` (TX path).
- `ip:port` is only an attribute (current endpoint), updated after a successful `open()` (roaming).
- On rekey the ticket is presented again, so an expired or revoked ticket ends the session within `REJECT_AFTER` (doc 03).

## 7. Timers and modes

| Parameter | Value | Reference / current |
|---|---|---|
| Handshake retry | 5 s + jitter (0–333 ms), new msg1 each attempt | WireGuard `REKEY_TIMEOUT`; app today: 4 attempts |
| Pending expiry | 10 s | today `[timers] pending_expiry_s` ([deploy/node.conf.example](../../deploy/node.conf.example), used at [main.cpp:527](../../main.cpp#L527)) |
| Keepalive | 15 s (sent in msg2 `keepalive_s`) | today 15 s (`KEEPALIVE_INTERVAL_MS`, app) |
| Rekey after | 120 s (client-initiated) | WireGuard `REKEY_AFTER_TIME`; doc 01 C4 |
| Reject after | 180 s | WireGuard `REJECT_AFTER_TIME`; replaces the v1 idle sweep `[timers] dead_after_s` = 60 s ([main.cpp:528](../../main.cpp#L528)) |

`auth_mode` in `node.conf` lets the handshake ship before tickets:

| Mode | Step 5 behaviour | Use |
|---|---|---|
| `open` | accept any `s_c` | local development only; refused unless built with `-DALLOW_OPEN_AUTH=ON` |
| `allowlist` | `s_c` must be in `allowed_clients` (file of public keys) | interim authentication until doc 03 lands |
| `ticket` | `TicketVerifier::verify(ticket, s_c, node)` | target |

## 8. Debuggability

- **Handshake ID:** `handshake_id` (8 B hex) appears in every log line for a session, on both sides. That lets you correlate client and server logs.
- **Drop-reason counters:** each drop reason is a counter in `Stats`, printed with the existing per-second stats ([utils/counter_definition.h](../../utils/counter_definition.h)): `HS_DROP_FORMAT, HS_DROP_MAC1, HS_DROP_DECRYPT, HS_DROP_AUTH_*, HS_DROP_REPLAY, HS_DROP_NO_CIPHER, HS_DROP_POOL_EMPTY`, plus `HS_CONFIRM_ACK`, `HS_CONFIRM_DATA_FALLBACK`.
- **Transition logging:** each state transition is logged at INFO, with the reason.
- **Key log (debug builds only):** with `-DENABLE_KEYLOG=ON` and `VPN_KEYLOG_FILE=<path>`, the server writes `handshake_id receiver_idx k_c2s k_s2c` per session, so a Wireshark dissector or offline script can decrypt captures. It's compiled out of release builds.

## 9. Code impact

Status after M4 in the last column. v1 code stays until M7 (Android moves to v2 in M6).

| Before | Change | Status |
|---|---|---|
| [crypto/DiffieHellman.h](../../crypto/DiffieHellman.h), [crypto/DiffieHellman.cpp](../../crypto/DiffieHellman.cpp), [crypto/KeyDerivation.*](../../crypto/KeyDerivation.h) | Removed. New `protocol/noise/{SymmetricState,HandshakeState}.{h,cpp}` on libsodium | Noise done: [protocol/noise/Noise.h](../../protocol/noise/Noise.h) (one file: `CipherState`, `SymmetricState`, `HandshakeIK`). Toy DH removed in M7 with v1 |
| [protocol/Handshake.h](../../protocol/Handshake.h) structs | v2 layouts (§3); v1 kept behind a demux on `ver` during migration | Done: [protocol/v2/Wire.h](../../protocol/v2/Wire.h); demux on the first byte in `main.cpp` |
| [sessions/session/ClientSession.*](../../sessions/session/ClientSession.h) (keyed by address + `client_magic`) | `HandshakeTable`: PENDING sessions by `sender_idx` and `s_c`, plus the msg2 cache | Done inside [protocol/v2/Server.h](../../protocol/v2/Server.h) (sessions by index, peers by `s_c`, msg2 cache); `ClientSession` stays for v1 |
| [sessions/client/Client_Manager.*](../../sessions/client/Client_Manager.h) | Indexes `receiver_idx` / `s_c` / `tun_ip`; `generateSessionId()` (sequential) replaced by random unique `u32` | Done in `v2::Server` (random indexes); `ClientManager` now only owns the shared IP pool and v1 clients |
| `handleHandshake` HELLO/ACK branches ([main.cpp:124-242](../../main.cpp#L124-L242)) | §5 pipeline; ACK handling per D3 | Done: `Server::onInit`, `Server::onTransport` |
| `handleUdpToTun` lookup ([main.cpp:58-77](../../main.cpp#L58-L77)) | Lookup by `receiver_idx`, then `open()`, then endpoint update | Done (v2); the v1 lookup is unchanged |
| Android app (separate repo `NetSpeedv3`): `MyVpnService.performHandshake()` in `MyVpnService.kt` | Kotlin initiator on Lazysodium; same test vectors | M6. The vector file is [tests/protocol/vectors/](../../tests/protocol/vectors/noise_ik_25519_chachapoly_blake2b.txt) |

## 10. Verification

Status: 1 and 3 done in M4 ([tests/protocol/](../../tests/README.md)); 2 waits for the Kotlin client (M6). Cross-implementation was also checked between the Linux server (libsodium 1.0.18) and the Windows client (MinGW, libsodium 1.0.20).

1. Noise test vectors for `Noise_IK_25519_ChaChaPoly_BLAKE2b` from the published vector sets (cacophony / snow; see the [Noise wiki test vectors][noise-vectors]). The same vector file is run in the C++ and Kotlin unit tests.
2. Cross-implementation test: C++ responder against a Kotlin initiator (JVM test harness), compared byte for byte.
3. Negative tests: bad mac1, tampered ciphertext, replayed msg1 (same and older ts), low-order `e_c`, no cipher intersection, empty pool. Each must increment exactly one drop counter.

## 11. As implemented (M4)

| Part | Where | Notes |
|---|---|---|
| Noise IK | [protocol/noise/Noise.h](../../protocol/noise/Noise.h) | Byte-identical to the [cacophony and snow vectors](../../tests/protocol/vectors/noise_ik_25519_chachapoly_blake2b.txt): handshake, handshake hash, 4 transport messages. HMAC/HKDF are also checked against Python `hmac` + `hashlib.blake2b`. |
| Wire format | [protocol/v2/Wire.h](../../protocol/v2/Wire.h) | Sizes as §3.2: HS_RESP 97 B, ACK 38 B, KEEPALIVE/BYE 30 B, HS_INIT 151 B (2 ciphers, no ticket) or 287 B with a 136 B ticket |
| Responder | [protocol/v2/Server.h](../../protocol/v2/Server.h) | Socket-free engine; `main.cpp` only does I/O |
| Initiator | [protocol/v2/Client.h](../../protocol/v2/Client.h) | Shared by [tools/vpn_client_v2.cpp](../../tools/vpn_client_v2.cpp) (Linux) and the [Windows client](../../clients/windows/README.md) |
| Replay window | [protocol/v2/ReplayWindow.h](../../protocol/v2/ReplayWindow.h) | RFC 6479, 32 × 64-bit blocks, window 1984 counters. Checked against a reference model over 200 000 random counters. |

Details the design left open, as built:

- **Byte order:**
  - `sender_idx`, `receiver_idx`, `counter`, `ticket_len` and `keepalive_s` are little-endian.
  - `tun_ip` is in network order, because it's an address.
  - TAI64N is big-endian per its spec (label = 2^62 + Unix seconds), so timestamps compare as bytes.
- **Strict payload parsing:**
  - `offer_n` must be 1–8.
  - The ticket can be at most 512 B.
  - There must be no trailing bytes.
  - A payload that decrypts but doesn't parse counts as `HS_DROP_FORMAT`.
- **ACK:** only counter 0 is accepted, and the payload must equal `handshake_id`; otherwise the packet counts as `tr_drop_ack`. Counters for DATA, KEEPALIVE and BYE start at 1 in both directions.
- **Anti-spoofing (added):** the inner IPv4 source of every DATA packet must be the client's own tunnel address; otherwise `tr_drop_src_ip`. Without this check, a client could inject packets carrying another client's source address.
- **Addresses belong to the client key `s_c`, not the session:**
  - A rekey keeps the IP.
  - A newer handshake replaces a pending one without freeing the IP.
  - The IP is freed when the client's last session goes: BYE, pending expiry, reject-after or idle.
- **Previous key:** after a rekey the old session stays accepted on receive, so in-flight packets still decrypt. It's removed when the next rekey supersedes it, or at reject-after. The server sends only with the current key.
- **Server keepalive:** the server sends `KEEPALIVE` after `keepalive_s` without sending anything. Clients therefore treat 3 × `keepalive_s` of silence as a lost session and reconnect.
- **Rekey:** the client starts a new HS_INIT at `rekey_after_s` and repeats it every 5 s until the HS_RESP arrives. Traffic keeps flowing under the old key in the meantime. If no rekey succeeds by 180 s, the client reconnects.
- **`auth_mode`:**
  - `allowlist` reads [`allowed_clients`](../../deploy/node.conf.example): one `<base64url key> [name]` per line.
  - `open` needs `-DALLOW_OPEN_AUTH=ON`.
  - `ticket` is rejected until M5.
  - Without a config file the node has no key, so v2 is off and only v1 runs, as before M3.
- **Protocol v1 alongside v2:** `[node] accept_v1 = true` by default, for clients that haven't been updated. Set it to `false` once every client speaks v2.
- **Key log:** with `-DENABLE_KEYLOG=ON` and `VPN_KEYLOG_FILE`, the server writes one line per confirmed session: `handshake_id receiver_idx k_c2s k_s2c`. The build prints a CMake warning when the option is on.

Still open:
- the mac2 cookie (D2, [parked P3](../plan/parked-discussions.md));
- tickets (M5);
- the Kotlin initiator (M6);
- experiments 003 (throughput, v1 vs v2) and 004 (HELLO flood vs mac1), deferred together with the other benchmarks.

## References

- [The Noise Protocol Framework (rev. 34)][noise] — §5 processing rules, §7.5 IK pattern, §4.3 HMAC/HKDF, §12.3 ChaChaPoly nonce, §8 identity hiding
- [Noise test vectors][noise-vectors]
- [WireGuard whitepaper][wg-paper] — §5.4 handshake, §5.4.4 mac1/mac2 and cookies, §6 timers
- [RFC 7748 — X25519][rfc7748]
- [RFC 7693 — BLAKE2][rfc7693] · [libsodium generic hashing (BLAKE2b)][sodium-hash] · [libsodium point*scalar (X25519)][sodium-scalarmult]
- [RFC 2104 — HMAC][rfc2104] · [RFC 5869 — HKDF][rfc5869]
- [RFC 8439 — ChaCha20-Poly1305][rfc8439]
- [TAI64N timestamp format][tai64]

[noise]: https://noiseprotocol.org/noise.html
[noise-vectors]: https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors
[wg-paper]: https://www.wireguard.com/papers/wireguard.pdf
[rfc7748]: https://www.rfc-editor.org/rfc/rfc7748
[rfc7693]: https://www.rfc-editor.org/rfc/rfc7693
[sodium-hash]: https://doc.libsodium.org/hashing/generic_hashing
[sodium-scalarmult]: https://doc.libsodium.org/advanced/scalar_multiplication
[rfc2104]: https://www.rfc-editor.org/rfc/rfc2104
[rfc5869]: https://www.rfc-editor.org/rfc/rfc5869
[rfc8439]: https://www.rfc-editor.org/rfc/rfc8439
[tai64]: https://cr.yp.to/libtai/tai64.html
