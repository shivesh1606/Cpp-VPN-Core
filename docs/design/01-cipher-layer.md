# 01 — Pluggable Transport Cipher Layer

| | |
|---|---|
| **Status** | Accepted (2026-11-08). Implemented through rollout step 2, plus step 4 (OpenSSL), in milestones M1–M2 ([plan](../plan/implementation-plan.md)). On the wire from M4. |
| **Scope** | Per-packet encryption of tunnel traffic (server engine + Android client) |
| **Depends on** | [02 — Handshake](README.md#index) (provides the session keys) |
| **Replaces** | `XorCipher` single-byte XOR ([crypto/XorCipher.cpp @ 76f900c](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/crypto/XorCipher.cpp); removed in M1, now `XorBackend` for protocol v1 only) |

---

## 1. Context: implementation before this design (`master` @ `76f900c`)

Links in this section point to that commit. Since M1, the XOR cipher sits behind `SessionLock` as [XorBackend](../../crypto/backends/XorBackend.h); protocol v1 on the wire is unchanged until M4.

| Aspect | Current code | Problem |
|---|---|---|
| Cipher | `result[i] = data[i] ^ xorkey` ([crypto/XorCipher.cpp:5-6](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/crypto/XorCipher.cpp#L5-L6)) | 1-byte key, 256-value keyspace. Brute-forced by testing for an IPv4 first byte `0x45`. |
| Key | `uint8_t xor_key` per client ([sessions/client/Client_Manager.h:24](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/sessions/client/Client_Manager.h#L24)) | Derived from DH with `P=127` ([crypto/DiffieHellman.h:7-8](../../crypto/DiffieHellman.h#L7-L8)) |
| Integrity | None | Forged or modified packets are accepted. A spoofed `PKT_DATA` carrying a guessed `session_id` triggers roaming ([main.cpp:49-60](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/main.cpp#L49-L60); still true on v1 today, at [main.cpp:57-68](../../main.cpp#L57-L68)) and redirects the victim's downstream traffic. |
| Call sites | decrypt [main.cpp:75](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/main.cpp#L75), encrypt [main.cpp:449](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/main.cpp#L449) | Hard-wired to the singleton `XorCipher::getInstance()` |

## 2. Decision

Replace XOR with an **AEAD** transport cipher behind an interface with three levels of selection:

```
compile time   CMake: libsodium (always, required), WITH_OPENSSL=ON (optional), ...
                 → which implementations EXIST in the binary (a single binary may hold several)
startup        node.conf: implementation chosen per algorithm
                 → which library runs (no rebuild)
per session    handshake negotiation: cipher_offer[] (HELLO) → cipher_id (WELCOME)
                 → which algorithm a given session uses (different clients may differ)
per packet     fixed; one virtual call into the session's lock
```

### 2.1 Algorithm vs implementation

The **wire `cipher_id` identifies the algorithm only**. The same algorithm from different libraries produces identical ciphertext for the same key, nonce, AAD and plaintext. That makes the implementation a local choice on each side, invisible to the peer.

| `cipher_id` | Algorithm | Spec | Implementations | Notes |
|---|---|---|---|---|
| 0 | `xor` | — | builtin | **Insecure.** Benchmark baseline only; rejected unless `allow_insecure_xor = true` |
| 1 | `chacha20poly1305` (IETF, 96-bit nonce) | [RFC 8439][rfc8439] | libsodium (default), OpenSSL | Default algorithm |
| 2 | `aes256gcm` | [NIST SP 800-38D][sp80038d] | OpenSSL, libsodium\* | \*libsodium needs hardware AES, checked at startup via `crypto_aead_aes256gcm_is_available()` ([libsodium AES-256-GCM][sodium-aesgcm]) |

### 2.2 Interfaces

```
                 ┌──────────────────────────────┐
                 │ CipherRegistry               │  algorithm id ⇄ name ⇄ {impl name → factory}
                 │ + resolve(cipher_id) → impl  │  populated from CMake options + node.conf
                 │ + offer() → cipher_id[]      │
                 └──────────────┬───────────────┘
                                │ 1..*
                 ┌──────────────▼───────────────┐
                 │ «interface» CipherBackend    │   one per (algorithm, library)
                 │ + algorithmId(), implName()  │
                 │ + newLock(key[32]) ──────────┼──────▶ «interface» SessionLock
                 └──────────────▲───────────────┘        + overhead()            // 16 for AEAD, 0 for xor
          ┌─────────────────────┼─────────────────────┐  + seal(ctr, aad, in, len, out)
  SodiumChaCha20Poly1305  OpenSslAeadBackend     XorBackend + open(ctr, aad, in, len, out) → bool
```

```cpp
// crypto/SessionLock.h (proposed)
class SessionLock {                        // one per direction per session
public:
    virtual ~SessionLock() = default;
    virtual size_t overhead() const = 0;   // tag bytes appended by seal()
    // out must hold len + overhead() bytes. Must not allocate.
    virtual void seal(uint64_t counter, const uint8_t* aad, size_t aad_len,
                      const uint8_t* in, size_t len, uint8_t* out) = 0;
    // Returns false on authentication failure (forged/modified/wrong key). Must not allocate.
    virtual bool open(uint64_t counter, const uint8_t* aad, size_t aad_len,
                      const uint8_t* in, size_t len, uint8_t* out) = 0;
};

class CipherBackend {
public:
    virtual ~CipherBackend() = default;
    virtual uint8_t     algorithmId() const = 0;   // wire cipher_id
    virtual const char* implName()    const = 0;   // "libsodium", "openssl", "builtin"
    virtual std::unique_ptr<SessionLock> newLock(const uint8_t key[32]) = 0;
};
```

Each session holds two locks: `rx` keyed with `k_c2s` and `tx` keyed with `k_s2c` (key derivation: doc 02).

**As implemented (M2).** All AEAD backends share one generic lock, so the nonce rule (C1) and the tag handling exist once:

```
CipherBackend ◀── AeadBackend<P>  ──newLock()──▶  AeadLock<P> : SessionLock
                                                    seal(ctr,…): counterNonce(ctr) → P.seal(nonce,…)
                                                    open(ctr,…): len ≥ 16 ? P.open(nonce,…) : false
P (primitive, 12-byte nonce in, no counter logic):
  SodiumChaCha20Poly1305   crypto_aead_chacha20poly1305_ietf_*        always
  SodiumAes256Gcm          crypto_aead_aes256gcm_*_afternm            if crypto_aead_aes256gcm_is_available()
  OpenSslChaCha20Poly1305  EVP_chacha20_poly1305()                    -DWITH_OPENSSL=ON
  OpenSslAes256Gcm         EVP_aes_256_gcm()                          -DWITH_OPENSSL=ON
```

| File | Content |
|---|---|
| [crypto/backends/AeadLock.h](../../crypto/backends/AeadLock.h) | `counterNonce`, `AeadLock<P>`, `AeadBackend<P>`; the primitive contract |
| [crypto/backends/SodiumAead.{h,cpp}](../../crypto/backends/SodiumAead.h) | libsodium primitives; `sodiumReady()`, `sodiumAes256GcmAvailable()` |
| [crypto/backends/OpenSslAead.{h,cpp}](../../crypto/backends/OpenSslAead.h) | OpenSSL EVP primitives; two pre-keyed `EVP_CIPHER_CTX` per lock (C3) |
| [crypto/CipherRegistry.cpp](../../crypto/CipherRegistry.cpp) | Registration order = default implementation and offer order: ChaCha20-Poly1305 (libsodium, openssl), AES-256-GCM (libsodium, openssl), xor |

- **Fail closed:** `seal()` stays `void`. If a library call fails internally (OpenSSL only; libsodium's calls cannot fail), the output is zero-filled, so the peer rejects the packet. On a failed `open()`, OpenSSL's already-decrypted bytes are wiped.
- **Key hygiene:** the key and the AES key schedule are zeroed on destruction (`sodium_memzero`, `EVP_CIPHER_CTX_free`).
- **Build:** libsodium is required and linked statically. OpenSSL (`-DWITH_OPENSSL=ON`, static `libcrypto.a`) is optional; the Docker build enables it.

### 2.3 Configuration (`node.conf`)

```ini
[crypto]
algorithms            = chacha20poly1305, aes256gcm   # server preference order for negotiation
impl.chacha20poly1305 = libsodium                     # switch to "openssl" to benchmark; clients unaffected
impl.aes256gcm        = openssl
allow_insecure_xor    = false                         # true only for baseline benchmarks
```

Negotiation rule: the server selects the first entry of `algorithms` that is also in the client's `cipher_offer[]`. If there's no intersection, the handshake fails.

**Status (M3):**
- The `[crypto]` keys are parsed and validated against the registry of the running binary ([config/NodeConfig.cpp](../../config/NodeConfig.cpp)):
  - unknown algorithms or implementations are startup errors;
  - `impl.X = openssl` needs `-DWITH_OPENSSL=ON`;
  - `xor` needs `allow_insecure_xor = true`.
- Negotiation and `impl.*` selection take effect with protocol v2 (M4). Until then the server warns that these keys are not used yet.
- All keys are documented in [deploy/node.conf.example](../../deploy/node.conf.example).

### 2.4 Out of scope (fixed, not pluggable)

Handshake and ticket primitives run once per connection. They're fixed so that both peers can always bootstrap: X25519, Ed25519 (ticket signatures), the handshake hash/KDF, and the handshake's own message AEAD. The exact handshake suite is decided in doc 02. Note that libsodium provides BLAKE2b (`crypto_generichash`) but not BLAKE2s.

## 3. Constraints on every implementation

| # | Constraint | Reason / reference |
|---|---|---|
| C1 | Nonce = `0x00000000 ‖ counter_u64_le` (96-bit). The counter is strictly increasing per direction and is never reused under a key. | Nonce reuse breaks both confidentiality and integrity ([RFC 8439 §4][rfc8439-s4], [RFC 5116 §3][rfc5116]). Same layout as WireGuard ([whitepaper §5.4.6][wg-paper]). |
| C2 | AAD = the 14-byte v2 transport header (`ver, type, receiver_idx, counter`) | Header fields are authenticated, so `receiver_idx` and `counter` can't be altered |
| C3 | `seal`/`open` perform no heap allocation. Per-key setup (e.g. an OpenSSL `EVP_CIPHER_CTX`) happens in `newLock()` at handshake time. | Zero-allocation hot path ([CONTRIBUTING.md](../../CONTRIBUTING.md)). Avoids repeating the key schedule per packet, so benchmarks compare like with like. |
| C4 | Rekey on time (≤ 120 s) and on message count. AES-GCM needs a far lower per-key record limit than ChaCha20-Poly1305. | [RFC 8446 §5.5][rfc8446-s55] key-usage limits; WireGuard `Rekey-After-Time` ([whitepaper §6.1][wg-paper]) |
| C5 | Each backend passes the known-answer tests before it's registered: RFC 8439 §2.8.2 (ChaCha20-Poly1305), the NIST GCM vectors (AES-256-GCM), and a cross-implementation test (seal with A, open with B). | Guarantees wire compatibility across libraries |
| C6 | Replay protection (sliding window) lives in the session layer, not in the lock | [RFC 6479][rfc6479]. The cipher layer stays stateless apart from the key. |

Wire cost: 16-byte tag per packet, plus the v2 header (14 B, up from 5 B). Inner MTU = 1500 − 20 (IPv4) − 8 (UDP) − 30 = 1442; the client should use 1420.

## 4. Code change map

| Area | Before (`76f900c`) | Change | Status |
|---|---|---|---|
| Cipher class | [crypto/XorCipher.h](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/crypto/XorCipher.h), [crypto/XorCipher.cpp](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/crypto/XorCipher.cpp) | Becomes `XorBackend` (id 0). Add `crypto/SessionLock.h`, `crypto/CipherRegistry.{h,cpp}`, `crypto/backends/*` | Done (M1, M2) |
| Client state | `uint8_t xor_key` ([Client_Manager.h:24](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/sessions/client/Client_Manager.h#L24)) | `std::unique_ptr<SessionLock> rx, tx; uint64_t tx_counter; ReplayWindow rx_window;` | Locks and counter done in M1 ([Client_Manager.h](../../sessions/client/Client_Manager.h)); replay window in M4 |
| RX path | `enc.crypt(...)` [main.cpp:75](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/main.cpp#L75) | `client->rx->open(...)`; on `false`, drop and count `auth_fail` | Done (M1): [main.cpp:91](../../main.cpp#L91), counter `rx_auth_fail` |
| TX path | `enc.crypt(...)` [main.cpp:449](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/main.cpp#L449) | `client->tx->seal(client->tx_counter++, ...)` | Done (M1): [main.cpp:636](../../main.cpp#L636) |
| Build | [CMakeLists.txt:37-53](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/CMakeLists.txt#L37-L53) | libsodium required (static link), `WITH_OPENSSL` (optional); new `crypto_bench` target | Done (M2). libsodium is unconditional; there is no `WITH_LIBSODIUM` switch |
| Docker | [Dockerfile:3-7](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/Dockerfile#L3-L7) | `apt-get install libsodium-dev` (static `libsodium.a`), optionally `libssl-dev` | Done (M2). Both installed; image built with `-DWITH_OPENSSL=ON` |
| Stats | `enc_cycles`/`dec_cycles` ([utils/counter_definition.h:62-63](https://github.com/shivesh1606/Cpp-VPN-Core/blob/76f900c/utils/counter_definition.h#L62-L63)) | Unchanged; works for any backend. Add an `auth_fail` counter. | Done (M1): `rx_auth_fail`, `udp_rx_truncated` |
| Android | XOR in `MyVpnService.kt` | Kotlin `SessionLock` interface; default implementation on [Lazysodium][lazysodium] | M6 |

## 5. Benchmark plan

`crypto_bench` (new CMake target) runs every registered backend over identical inputs:

```
$ ./crypto_bench --sizes 64,512,1400 --count 1000000
backend                          size   cycles/pkt   cycles/byte   Gbps/core
xor/builtin                      1400   ...          ...           ...
chacha20poly1305/libsodium       1400   ...          ...           ...
chacha20poly1305/openssl         1400   ...          ...           ...
aes256gcm/openssl                1400   ...          ...           ...
```

- Implemented in [tools/crypto_bench.cpp](../../tools/crypto_bench.cpp). It times the real `SessionLock` objects (one virtual call, 14-byte AAD, counter nonce), so a new backend is benchmarked as soon as it is registered. Ops: `seal`, `open`, `open-forged` (flipped tag). Median of `--runs` rounds, with spread.
- Timing uses `CLOCK_MONOTONIC` and `__rdtsc()` directly, not `RDTSC()` from [utils/profiling.h](../../utils/profiling.h), which is compiled out unless `ENABLE_PROFILING=ON`. On arm64 only ns are reported.
- Live in-server comparison: swap `impl.*` in `node.conf` and read `enc_cyc_per_pkt` / `dec_cyc_per_pkt` from the stats log.

### 5.1 Baseline measurements (2026-11-08, pre-implementation)

Standalone micro-benchmark run before any engine change, to size the per-packet cost of this design. Full method, raw output and reproduction steps: [experiments/001-crypto-per-packet-cost](../../experiments/001-crypto-per-packet-cost/README.md).

**Environment**
- CPU: Intel i7-11800H, WSL2 Ubuntu 22.04, pinned to one core
- Build: gcc 11.4 `-O2` (same flags as [CMakeLists.txt:35](../../CMakeLists.txt#L35)), libsodium 1.0.18 (Ubuntu package), statically linked
- Method: 1 M iterations after a 10% warm-up; mean of 2 runs. Run-to-run spread ≤ 5%.

Mean cost per operation in ns:

| Operation | 64 B | 512 B | 1400 B |
|---|---|---|---|
| XOR, current `XorCipher::crypt` at `-O2` (not vectorized by GCC 11) | 30 | 193 | 511 |
| XOR, same code at `-O3` (vectorized), for reference | 3 | 11 | 36 |
| ChaCha20-Poly1305 IETF seal | 287 | 500 | 1173 |
| ChaCha20-Poly1305 IETF open (valid) | 294 | 487 | 1189 |
| ChaCha20-Poly1305 IETF open (forged → drop) | 210 | 324 | 527 |
| AES-256-GCM seal (AES-NI) | 177 | 314 | 754 |
| AES-256-GCM open (valid) | 190 | 315 | 805 |

| Per-packet bookkeeping and context | ns |
|---|---|
| Replay window check + update (2048-bit, RFC 6479 style) | 2 |
| `sendto()` 1400 B on loopback (kernel cost, for context) | 1240–1490 |

| Per handshake (once per connect and per 120 s rekey) | µs |
|---|---|
| X25519 `crypto_scalarmult` (Noise IK: 4 per side) | 30 |
| Ed25519 verify (ticket, node side only) | 40 |
| Node total ≈ 4 × X25519 + Ed25519 + hashes | ≈ 165 |

**Takeaways**
- At 1400 B, ChaCha20-Poly1305 adds about +0.65 µs per direction compared with today's `-O2` XOR. AES-256-GCM adds about +0.25 µs.
- Forged packets are rejected at roughly half the cost of a valid open, because the tag is checked before decryption.
- Crypto stays below the kernel's per-datagram cost.
- The handshake, amortized over the 120 s rekey interval, is about 1.4 µs per second per client.
- libsodium 1.0.18 provides AES-256-GCM only on x86 with AES-NI. ARM nodes (e.g. Ampere) need the OpenSSL backend for AES-GCM, or they negotiate ChaCha20-Poly1305.

Re-run these numbers on target node hardware once `crypto_bench` exists. Free-tier shared-core VMs will be slower.

### 5.2 `crypto_bench` results (2026-11-08, M2)

Same laptop, now through the engine's `SessionLock` code, with all four AEAD backends. Full data and method: [experiments/002-crypto-bench-backends](../../experiments/002-crypto-bench-backends/README.md).

| Median ns per op, Release build | seal 64 B | seal 1400 B | open 1400 B | forged 1400 B |
|---|---|---|---|---|
| chacha20poly1305 / libsodium | 300 | 1217 | 1242 | 566 |
| chacha20poly1305 / openssl | 357 | 885 | 903 | 905 |
| aes256gcm / libsodium | 134 | 704 | 760 | 305 |
| aes256gcm / openssl | 204 | 483 | 448 | 456 |
| xor / builtin (`-O3`, as in the Docker image) | 5 | 41 | 38 | — |

- **Library choice depends on packet size.** OpenSSL is cheaper at 1400 B; libsodium is cheaper at 64 B and drops forged packets at about half the cost of a valid open, because it checks the tag first. The default stays libsodium until target-node data exists; M3's `impl.*` switches it without a rebuild.
- **Mixing libraries needed a fix.** OpenSSL's AVX code slowed the libsodium AES-NI code that ran after it by 1.7×. The OpenSSL backend now issues `vzeroupper` after each call ([VectorState.h](../../crypto/backends/VectorState.h)).
- **Release builds are `-O3`.** The production XOR baseline is 41 ns, not the `-O2` 511 ns in §5.1.

## 6. Rollout

1. Introduce `SessionLock`/`CipherBackend`/`CipherRegistry`, and move XOR behind it as id 0. No wire change; existing clients keep working. **Done (M1).**
2. Add the libsodium ChaCha20-Poly1305 backend, the KAT tests and `crypto_bench`. **Done (M2)**, together with libsodium AES-256-GCM.
3. Enable on the wire together with protocol v2 (doc 02): v2 header, negotiation fields, replay window. *(M4)*
4. Optional: OpenSSL backends for comparison. **Done (M2)**, behind `-DWITH_OPENSSL=ON`.

## References

- [RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols][rfc8439]
- [RFC 5116 — An Interface and Algorithms for Authenticated Encryption][rfc5116]
- [NIST SP 800-38D — Galois/Counter Mode (GCM)][sp80038d]
- [RFC 8446 §5.5 — TLS 1.3 limits on key usage][rfc8446-s55]
- [RFC 6479 — IPsec Anti-Replay Algorithm without Bit Shifting][rfc6479]
- [WireGuard whitepaper][wg-paper] · [WireGuard protocol overview][wg-protocol]
- [libsodium — AEAD constructions][sodium-aead] · [IETF ChaCha20-Poly1305][sodium-chacha] · [AES-256-GCM][sodium-aesgcm]
- [OpenSSL — EVP AEAD interface][openssl-evp]
- [Lazysodium for Android][lazysodium]

[rfc8439]: https://www.rfc-editor.org/rfc/rfc8439
[rfc8439-s4]: https://www.rfc-editor.org/rfc/rfc8439#section-4
[rfc5116]: https://www.rfc-editor.org/rfc/rfc5116
[sp80038d]: https://csrc.nist.gov/pubs/sp/800/38/d/final
[rfc8446-s55]: https://www.rfc-editor.org/rfc/rfc8446#section-5.5
[rfc6479]: https://www.rfc-editor.org/rfc/rfc6479
[wg-paper]: https://www.wireguard.com/papers/wireguard.pdf
[wg-protocol]: https://www.wireguard.com/protocol/
[sodium-aead]: https://doc.libsodium.org/secret-key_cryptography/aead
[sodium-chacha]: https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction
[sodium-aesgcm]: https://doc.libsodium.org/secret-key_cryptography/aead/aes-256-gcm
[openssl-evp]: https://docs.openssl.org/3.0/man3/EVP_EncryptInit/
[lazysodium]: https://github.com/terl/lazysodium-android
