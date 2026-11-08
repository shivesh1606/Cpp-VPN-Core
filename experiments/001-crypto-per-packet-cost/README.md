# 001 — Per-packet crypto cost: XOR vs AEAD

| | |
|---|---|
| **Date** | 2026-11-08 |
| **Status** | Done on a dev laptop. Runs on target nodes are pending (experiment 002). |
| **Informs** | [Design 01: cipher layer](../../docs/design/01-cipher-layer.md) §5.1; [Design 02: handshake](../../docs/design/02-handshake.md) (handshake cost) |

## Question

How much CPU time per data packet does replacing the current 1-byte XOR ([crypto/XorCipher.cpp](../../crypto/XorCipher.cpp)) with an AEAD cipher add? How does that compare with the kernel cost of moving the packet?

## Hypothesis

AEAD adds about 1 µs per 1400 B packet, which is the same order as one UDP send syscall. The handshake cost is negligible once amortized over the rekey interval.

## Environment

| Item | Value |
|---|---|
| CPU | Intel Core i7-11800H @ 2.30 GHz (TSC 2.3 GHz; core turbo up to 4.6 GHz) |
| OS | WSL2, Ubuntu 22.04.3 LTS, on Windows 11 |
| Compiler | gcc 11.4.0, `-O2` (same as [CMakeLists.txt:35](../../CMakeLists.txt#L35)); `-O3` run for the XOR reference only |
| Library | libsodium 1.0.18 (Ubuntu package `libsodium-dev 1.0.18-1ubuntu0.22.04.1`), statically linked |
| Pinning | `taskset -c 2` |

## Method

[pkt_bench.c](pkt_bench.c), built and run by [run.sh](run.sh).

- Each operation runs for 1,000,000 iterations after a 10% warm-up. The handshake primitives use 20,000 iterations, and the `sendto` context measurement 200,000.
- Each result is the mean wall time (`CLOCK_MONOTONIC`) and mean TSC ticks. Note that TSC ticks are not core cycles when the core is boosting.
- **XOR:** a verbatim copy of `XorCipher::crypt`, compiled `noinline`.
- **AEAD:**
  - `crypto_aead_chacha20poly1305_ietf_{encrypt,decrypt}` and `crypto_aead_aes256gcm_{encrypt,decrypt}`;
  - 14-byte AAD (the v2 transport header) and the nonce layout `0⁴ ‖ counter_le64` (design 01, C1/C2);
  - "forged" means one tag byte flipped before `decrypt`.
- **Replay window:** a 2048-bit bitmap in the RFC 6479 style, with in-order counters.
- **Context:** `sendto()` of 1400 B to a bound loopback socket, measuring kernel cost only.
- Two full runs, plus one `-O3` run for the XOR reference. The raw output is in [results/](results/).

## Results

Mean of runs 1 and 2, in ns per operation (run-to-run spread ≤ 5%):

| Operation | 64 B | 512 B | 1400 B |
|---|---|---|---|
| XOR, current code, `-O2` (GCC 11 doesn't vectorize it) | 30 | 193 | 511 |
| XOR, same code, `-O3` (vectorized), reference | 3 | 11 | 36 |
| ChaCha20-Poly1305 seal | 287 | 500 | 1173 |
| ChaCha20-Poly1305 open, valid | 294 | 487 | 1189 |
| ChaCha20-Poly1305 open, forged (drop) | 210 | 324 | 527 |
| AES-256-GCM seal (AES-NI) | 177 | 314 | 754 |
| AES-256-GCM open, valid | 190 | 315 | 805 |

Added cost per direction, compared with the current `-O2` XOR:

| Payload | ChaCha20-Poly1305 | AES-256-GCM |
|---|---|---|
| 64 B | +260 ns | +150 ns |
| 512 B | +300 ns | +120 ns |
| 1400 B | +670 ns | +270 ns |

| Other | Value |
|---|---|
| Replay window check + update | 2 ns |
| `sendto()` 1400 B, loopback | 1241–1494 ns |
| X25519 `crypto_scalarmult` | 29–31 µs |
| Ed25519 verify | 40–42 µs |
| BLAKE2b-512 of 64 B | 113–121 ns |
| Node handshake total (4 × X25519 + Ed25519 + hashes, estimated) | ≈ 165 µs per connect or rekey, ≈ 1.4 µs/s per client at a 120 s rekey |

## Conclusion

- The hypothesis holds: AEAD adds well under one syscall's worth of time per packet. At 1400 B that's ChaCha20 +0.67 µs or AES-GCM +0.27 µs per direction, against a kernel `sendto` of 1.2–1.5 µs.
- Header growth from 5 to 30 B costs more than the CPU: about 1.8% of bandwidth at 1400 B, and about 2 µs of serialization at 100 Mbps.
- Forged packets are rejected at about 45% of the cost of a valid open, because the tag is checked before decryption. That's good for DoS resistance.
- AES-256-GCM is about 1.5× faster than ChaCha20-Poly1305 on this x86 with AES-NI. libsodium 1.0.18 offers AES-GCM only on x86 with AES-NI. That supports the pluggable-backend and negotiation design (design 01).
- Side finding: the current XOR is 14× slower at `-O2` than at `-O3`. Earlier XOR baselines therefore understate what an optimized v1 could do.

## Threats to validity

- Laptop CPU with turbo boost, run under WSL2. Absolute numbers will differ on shared-core cloud VMs (experiment 002).
- The loopback `sendto` cost excludes NIC and driver costs. A real path costs more, which makes crypto relatively smaller.
- Micro-benchmark with hot caches. The engine's real working set may add cache misses.

## Reproduce

```bash
# Linux or WSL (no root needed: fetches the Ubuntu libsodium package locally)
bash experiments/001-crypto-per-packet-cost/run.sh | tee experiments/001-crypto-per-packet-cost/results/$(date +%F)_$(hostname)_<env>.txt
```
