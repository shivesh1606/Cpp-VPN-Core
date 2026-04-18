# Cpp-VPN-Core: Bugs, Improvements & Upgrade Roadmap

A comprehensive audit of the codebase covering confirmed defects, code quality improvements, and a prioritized upgrade path toward industry-standard quality.

---

## Part 1: Bugs (Confirmed Defects)

### BUG-1: Buffer Over-Read in Logger (Security / Crash)

**File:** `utils/logger.cpp` — `log_write()`

`vsnprintf` returns the number of characters that *would have been written* if the buffer was large enough. If a log message exceeds 511 chars, `msg_len` can be e.g. 600, but only 511 bytes were actually written into `msg[512]`. The subsequent `memcpy` reads past the stack buffer.

```cpp
char msg[512];
int msg_len = vsnprintf(msg, sizeof(msg), fmt, ap); // can return > 511
// ...
memcpy(g_buf + g_pos, msg, msg_len); // reads msg_len bytes from a 512-byte buffer
```

**Fix:** Clamp `msg_len` after `vsnprintf`:

```cpp
if (msg_len < 0) return;
if ((size_t)msg_len >= sizeof(msg))
    msg_len = sizeof(msg) - 1;
```

---

### BUG-2: `removeClient()` Declared but Never Defined (Linker Error)

**File:** `sessions/client/Client_Manager.h` line 146

The header declares `void removeClient(uint32_t serverAssignedIp);` but there is no implementation in `Client_Manager.cpp`. Any call will fail at link time.

---

### BUG-3: Global Variables in Header Cause ODR Violations

**File:** `crypto/DiffieHellman.h` lines 7–8

```cpp
long long int P=127;
long long int G=9;
```

These are non-const, non-inline global variables defined in a header. If included by two or more `.cpp` files, this causes duplicate symbol linker errors or undefined behavior.

**Fix:** Change to `inline constexpr long long int P = 127;` or move to a `.cpp` file.

---

### BUG-4: `#include` Placed Before Include Guard

**Files:** `crypto/XorCipher.h`, `utils/profiling.h`

```cpp
#include <cstdint>   // processed every time
#ifndef XORCIPHER_H  // guard only protects what follows
```

The `#include` is processed on every inclusion regardless of the guard.

**Fix:** Move the `#include` inside the guard.

---

### BUG-5: `#pragma pack(1)` on Internal Struct Causes Misaligned Access

**File:** `sessions/session/ClientSession.h` — `SessionState`

`SessionState` contains `sockaddr_in` and `time_t`, both requiring natural alignment. Packing to 1-byte alignment causes:

- Misaligned access (UB on strict-alignment architectures, performance penalty on x86)
- If a pointer to the packed `sockaddr_in` is passed to a system call, it is undefined behavior

This struct is internal session state — it is never sent over the wire. Packing provides zero benefit.

**Fix:** Remove `#pragma pack(push, 1)` / `#pragma pack(pop)` from this struct.

---

### BUG-6: `addClient` Collision Path Destroys the Existing Client

**File:** `sessions/client/Client_Manager.cpp` lines 37–45

If `vpn_to_client.emplace()` fails (IP already in the map), `freeIp()` is called. But `freeIp()` looks up the IP in the map and **erases the existing legitimate client's session and UDP mappings**, then frees the pool entry.

A failed add should only reset the pool entry, not call the full `freeIp`.

---

### BUG-7: `ClientSession::addSession` Allows Duplicate Sessions

**File:** `sessions/session/ClientSession.cpp` — `addSession()`

No duplicate check before `sessions_.push_back(s)`. If a client sends multiple HELLO packets from the same address, multiple entries are appended. Each one reserves a VPN IP, draining the pool. `getSession` returns only the first match; duplicates become orphaned and leak reserved IPs permanently.

---

### BUG-8: RESERVED IPs Are Never Reclaimed

**File:** `sessions/client/Client_Manager.cpp` — `getNextAvailableIp()`

IPs go `FREE → RESERVED` during handshake, then `RESERVED → ACTIVE` on `addClient`. If a handshake never completes (client disappears after HELLO), the IP stays RESERVED forever. `eraseExpiredSessions` cleans up `SessionState` but never frees the RESERVED IP back to the pool.

**Fix:** `eraseExpiredSessions` must also call `freeIp()` for the associated reserved IP.

---

### BUG-9: `rand()` Used for Cryptographic Key Material

**File:** `crypto/DiffieHellman.h` — `randomNumGen()`

`rand()` is a deterministic PRNG typically seeded with `time(nullptr)`. An attacker who knows the approximate server start time can predict every DH private key.

**Fix:** Use `getrandom(2)`, `/dev/urandom`, or `libsodium`'s `randombytes_buf()`.

---

### BUG-10: `using namespace std` in a Header File

**File:** `crypto/DiffieHellman.h` line 6

Every file that includes this header gets the entire `std` namespace dumped into its global scope, potentially causing silent name collisions.

**Fix:** Remove `using namespace std;` and qualify usages explicitly.

---

## Part 2: Code Improvements

### IMP-1: `XorCipher` Singleton Is Unnecessary

The class holds zero state. `crypt()` doesn't touch any member variables. The singleton forces indirection for something that should be a plain static function or free function.

### IMP-2: `xorkey` Passed by Reference Instead of Value

`uint8_t &xorkey` in `XorCipher::crypt()` — passing a 1-byte value by reference (8-byte pointer on 64-bit) is slower than passing by value and prevents compiler optimizations.

### IMP-3: `SocketManager` and `TunDevice` Should Be Namespaces

Both classes have only static methods and constructors/destructors that do nothing useful. They should be namespaces with free functions.

### IMP-4: No RAII for File Descriptors

`createUdpSocket` and `TunDevice::create` return raw `int` fds. If the caller forgets to close them or an exception is thrown, they leak. Should use a RAII wrapper (e.g. `UniqueFd`).

### IMP-5: Missing Socket Options

`createUdpSocket` should set:

- `SO_REUSEADDR` — allows restart after crash without waiting for TIME_WAIT
- `O_NONBLOCK` — README claims non-blocking I/O but socket is created blocking
- `SO_RCVBUF` / `SO_SNDBUF` — increased buffer sizes for high-throughput workloads

### IMP-6: Mixed Error Handling Strategies

- `SocketManager` returns `-1` on error
- `TunDevice` throws `std::runtime_error`
- `ClientManager` returns `nullptr`

Pick one convention and use it consistently.

### IMP-7: `global_stats` Is Not Thread-Safe

All counters are plain `uint64_t`. If the engine ever moves to multi-threaded processing, every counter increment is a data race. Should use `std::atomic<uint64_t>` or per-thread stats.

### IMP-8: Logger Has No Level Filtering

The `lvl` parameter in `log_write()` is accepted but never checked against a configurable threshold. Every `LOG_DEBUG` message goes to output in production.

### IMP-9: `reset_Stats()` Doesn't Reset Min/Max

`max_udp_mbps`, `min_udp_mbps`, `max_tun_mbps`, `min_tun_mbps`, `max_avg_pkts_per_rx_batch`, `max_avg_pkts_per_tx_batch` are never reset. They accumulate across the entire server lifetime.

### IMP-10: Include Guard Inconsistency

The project mixes `#pragma once` (`logger.h`, `Client_Manager.h`) with `#ifndef`/`#define` guards (everything else). Use one convention consistently.

### IMP-11: Unused `#include <string>` in `Client_Manager.h`

`std::string` is never used in the class. Increases compilation time for no reason.

### IMP-12: `print_Stats()` Format Specifiers Are Not Portable

`%lu` for `uint64_t` is only correct on LP64 (most 64-bit Linux). Should use `PRIu64` from `<cinttypes>` for portability.

---

## Part 3: Future Upgrades (Priority Order)

### P0 — Critical Security (Must-Have Before Any Real Use)

| # | Upgrade | Rationale |
|---|---------|-----------|
| 1 | **Replace XOR cipher with AES-256-GCM or ChaCha20-Poly1305** | XOR provides zero security. A single known-plaintext byte (e.g. IP header `0x45`) reveals the key. Industry VPNs use AEAD. |
| 2 | **Replace DH with ECDH (Curve25519 / X25519)** | P=127 gives ~7 bits of security. Industry standard is 128+. X25519 is fast, constant-time, and used by WireGuard/TLS 1.3. |
| 3 | **Replace `rand()` with CSPRNG** | Use `getrandom(2)`, `/dev/urandom`, or libsodium's `randombytes_buf()`. |
| 4 | **Add packet authentication (HMAC/AEAD)** | Zero integrity verification on data packets. Bit-flipping attacks are trivial with XOR. AEAD ciphers solve this. |
| 5 | **Add replay protection** | Without sequence numbers and a sliding window, attackers can capture and re-send valid packets. Standard: 64-bit sequence number + anti-replay window (RFC 6479). |
| 6 | **Implement proper key derivation (HKDF)** | The `KeyDerivation` module is empty. DH shared secret should never be used directly — derive separate keys via HKDF-SHA256. |

### P1 — Reliability (Production Readiness)

| # | Upgrade | Rationale |
|---|---------|-----------|
| 7 | **Implement keepalive / heartbeat** | No mechanism to detect dead clients. Stale sessions and IPs accumulate until pool exhaustion. |
| 8 | **Fix RESERVED IP reclamation** | Handshake failures permanently leak pool IPs. `eraseExpiredSessions` must also free the associated reserved IP. |
| 9 | **Add connection limits and rate limiting** | Unlimited HELLO floods can exhaust the IP pool. Add per-IP rate limits and max concurrent connections. |
| 10 | **Implement graceful disconnect (PKT_BYE)** | `PKT_BYE` is defined but not handled. Implement proper cleanup on disconnect. |
| 11 | **Add configuration file** | Port, IP pool range, pool size, log path, timeouts are all hardcoded. Use a config file (TOML/YAML/INI). |
| 12 | **Add a `CMakeLists.txt` to this repo** | Currently the build config lives outside the repo, making the project unbuildable by anyone else. |

### P2 — Scalability (High-Performance at Scale)

| # | Upgrade | Rationale |
|---|---------|-----------|
| 13 | **Replace `select()` with `epoll`** | `select()` is O(n) and limited to 1024 fds. `epoll` is O(1) and handles tens of thousands of connections. |
| 14 | **Consider `io_uring`** | Eliminates even the syscall overhead of `epoll` via shared memory rings. |
| 15 | **Replace `ClientSession` vector with hash map** | O(n) linear search on every handshake packet doesn't scale. Use `std::unordered_map` like `ClientManager`. |
| 16 | **Add multi-threaded packet processing** | Single-threaded design can't saturate modern multi-core CPUs. Options: thread-per-core with session affinity or work-stealing pool. |
| 17 | **Support `SO_REUSEPORT`** | Multiple threads bind to the same UDP port with kernel-level load balancing. |
| 18 | **Make counters thread-safe** | `std::atomic` or per-thread stat structs with periodic aggregation. |

### P3 — Protocol Maturity

| # | Upgrade | Rationale |
|---|---------|-----------|
| 19 | **Add protocol version field** | No version in the packet header. Future protocol changes will break old clients without it. |
| 20 | **Implement MTU/PMTU discovery** | Hardcoded packet sizes cause fragmentation or silent drops on smaller MTU paths. (RFC 1191) |
| 21 | **Add IPv6 support** | Entire codebase assumes `sockaddr_in` (IPv4 only). Dual-stack is required for modern networks. |
| 22 | **Add packet compression (LZ4)** | Reduces bandwidth for compressible traffic. |
| 23 | **Add session resumption** | Server restart forces all clients to re-handshake. Session tickets allow faster recovery. |

### P4 — Operational Excellence

| # | Upgrade | Rationale |
|---|---------|-----------|
| 24 | **Add unit tests** | Zero tests today. Use Google Test or Catch2 for `ClientManager`, `XorCipher`, `DiffieHellman`, packet parsing. |
| 25 | **Add integration tests** | Server + simulated client: verify handshake, data flow, roaming. |
| 26 | **Add log rotation** | Logger appends forever. Implement size-based rotation or integrate with `logrotate`. |
| 27 | **Add metrics export** | Prometheus `/metrics` endpoint or StatsD for real-time dashboards. |
| 28 | **Add CI/CD pipeline** | GitHub Actions: build, `clang-tidy`, tests, `-fsanitize=address`, memory leak checks. |
| 29 | **Fuzz test the packet parser** | `PacketHeader` parsing is a critical attack surface. Use `libFuzzer` or AFL. |

---

## Summary

| Category | Count | Most Critical |
|----------|-------|---------------|
| **Bugs** | 10 | Buffer over-read in logger, missing `removeClient` impl, RESERVED IP leak, collision destroys existing client |
| **Improvements** | 12 | RAII for fds, thread safety, log level filtering, consistent error handling |
| **Security Upgrades** | 6 | Replace XOR + DH with real crypto (P0) — single biggest gap to industry standard |
| **Reliability** | 6 | Keepalives, IP reclamation, rate limiting |
| **Scalability** | 6 | epoll, multi-threading, io_uring |
| **Protocol** | 5 | Versioning, MTU, IPv6 |
| **Operations** | 6 | Tests, CI, fuzzing, metrics |

> **Recommended first step:** Integrate [libsodium](https://doc.libsodium.org/). Its `crypto_aead_chacha20poly1305` + `crypto_kx` replaces the entire `crypto/` module in ~50 lines and provides industry-grade authenticated encryption, key exchange, and key derivation.
