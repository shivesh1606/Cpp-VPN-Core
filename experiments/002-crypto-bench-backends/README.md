# 002 — `crypto_bench`: every cipher backend through the engine's code

| | |
|---|---|
| **Date** | 2026-11-08 |
| **Status** | Done on a dev laptop (x86, AVX-512). **Deferred (2026-11-08):** GCP e2-micro (x86 shared core) and Oracle A1 (arm64). Recipe below. |
| **Informs** | [Design 01 §5](../../docs/design/01-cipher-layer.md#5-benchmark-plan); default `impl.*` choices for `node.conf` (plan M3) |
| **Follows** | [001](../001-crypto-per-packet-cost/README.md) (standalone libsodium micro-benchmark, before any engine change) |

## Question

For each wire algorithm, which library (libsodium or OpenSSL) is cheaper per packet when called through the engine's real `SessionLock` code? Does that depend on packet size or on CPU?

## Hypothesis

OpenSSL is faster on large packets on CPUs with wide vector units: it has AVX-512 ChaCha20 and VAES/VPCLMULQDQ GCM, which libsodium 1.0.18 lacks. libsodium is faster on small packets, because the EVP API costs more per call. Both stay below the kernel's per-datagram cost (≈ 1.2–1.5 µs, experiment 001).

## Environment

| Item | Value |
|---|---|
| CPU | Intel Core i7-11800H (Tiger Lake, AVX-512, VAES), TSC 2.3 GHz, turbo up to 4.6 GHz |
| OS | WSL2 Ubuntu 22.04, kernel 6.18 (microsoft-standard-WSL2), Windows 11 host |
| Compiler | gcc 11.4.0. Two builds: `Release` = `-O2 -O3 -DNDEBUG` (what the Docker image uses), and no build type = `-O2` (what `scripts/runbuild.sh` uses) |
| Libraries | libsodium 1.0.18 (Ubuntu `libsodium-dev`, static); OpenSSL 3.0.2 (Ubuntu `libssl-dev`, static `libcrypto.a`) |
| Code | M2 working tree on top of `838ab6f`, committed as the first commit of branch `feature/m2-libsodium`. The results files say `838ab6f`, because the dirty-tree marker was added to `run.sh` afterwards. |
| Pinning | `taskset -c 2` |

## Method

- **Tool:** [tools/crypto_bench.cpp](../../tools/crypto_bench.cpp), built by [run.sh](run.sh) with `-DWITH_OPENSSL=ON`.
- **Code path:** each row times one op through `CipherBackend::newLock()` → `SessionLock::seal/open`. That's one virtual call, a 14-byte AAD (the v2 header size) and the counter nonce, exactly as the server will call it.
- **Ops:**
  - `seal`: the counter increments per call.
  - `open`: a valid packet.
  - `open-forged`: the same packet with one tag bit flipped. This is the cost of dropping a forged packet.
- **Counts:** 10⁶ ops × 3 runs per row, after 10⁵ warm-up ops. The **median** run is reported; spread = (max − min) / median.
- **Isolation:** before each row the bench executes `vzeroupper`. Without it, rows depend on which backend ran before them; see finding 3.

## Results (Release build, median ns per op)

Raw output:
- [results/2026-11-08_i7-11800H_wsl2_release.txt](results/2026-11-08_i7-11800H_wsl2_release.txt)
- [results/2026-11-08_i7-11800H_wsl2_default-O2.txt](results/2026-11-08_i7-11800H_wsl2_default-O2.txt)

| Backend | seal 64 B | open 64 B | seal 512 B | open 512 B | seal 1400 B | open 1400 B | forged 1400 B |
|---|---|---|---|---|---|---|---|
| chacha20poly1305 / libsodium | **300** | **305** | 508 | 497 | 1217 | 1242 | **566** |
| chacha20poly1305 / openssl | 357 | 366 | **476** | **486** | **885** | **903** | 905 |
| aes256gcm / libsodium | **134** | **131** | **256** | **280** | 704 | 760 | **305** |
| aes256gcm / openssl | 204 | 196 | 308 | 285 | **483** | **448** | 456 |
| xor / builtin, `-O3` (Docker image) | 5 | 4 | 21 | 12 | 41 | 38 | — (no integrity) |
| xor / builtin, `-O2` (`runbuild.sh`) | 30 | 32 | 199 | 197 | 556 | 541 | — |

Bold = cheaper library for that algorithm and column. AEAD rows match between the two builds within ±10% (28 of 36 rows within ±5%), which is the run-to-run noise level, because library code is precompiled. Spread is 1–12% for most rows (WSL2 on a laptop); a few rows reach 20–87% and are marked in the raw files. Treat differences under about 10% as noise.

## Findings

1. **The fastest library depends on packet size.** At 1400 B, OpenSSL is 27% cheaper for ChaCha20-Poly1305 and 31% cheaper for AES-256-GCM, thanks to wider vector code. At 64 B, libsodium is 16% (ChaCha) and 34% (AES) cheaper, because each EVP call costs about 150 ns of fixed overhead. For ChaCha the crossover is near 512 B. Server traffic is mixed: a TCP download is mostly 1400 B `seal` downstream and about 64 B `open` (ACKs) upstream. A per-direction or per-size choice isn't worth the complexity yet; this needs target-node numbers.
2. **The cost of dropping a forged packet differs by library.**
   - libsodium checks the tag before decrypting, so a forged packet costs 0.40–0.46× a valid `open`.
   - OpenSSL's EVP API decrypts first and verifies at `Final`, so a forged packet costs the same as a valid one.

   Under a flood of forged DATA packets, libsodium drops traffic at about half the CPU cost. This is relevant to experiment 004.
3. **Mixing libraries in one process slows libsodium AES-GCM by 1.7×. Fixed.** After any OpenSSL call, libsodium's AES-256-GCM went from 741 to 1260 ns (1400 B seal). OpenSSL's AVX-512 code leaves the upper vector registers dirty, and the CPU then penalizes the legacy-SSE AES-NI instructions in libsodium 1.0.18.
   - **Evidence:**
     - `crypto_bench --no-vzeroupper` before the fix: libsodium AES 1260 ns.
     - With `vzeroupper` between rows: 741 ns.
     - After the engine fix, *with* `--no-vzeroupper`: 704 ns.
   - **Fix:** the OpenSSL backend now executes `vzeroupper` after each call ([crypto/backends/VectorState.h](../../crypto/backends/VectorState.h)), which costs about one cycle. This matters once `node.conf` (M3) can pick OpenSSL for one algorithm and libsodium for another in the same process.
4. **Release builds are `-O3`, not `-O2`.** CMake appends `CMAKE_CXX_FLAGS_RELEASE` (`-O3 -DNDEBUG`) to the project's `-O2`. The Docker image's XOR is therefore vectorized (41 ns at 1400 B), not the 511–556 ns `-O2` loop. Experiment 001's "current XOR" baseline applies to `scripts/runbuild.sh` builds only; its README now has a note.
5. **Pre-expanding the key (constraint C3) pays off.** libsodium AES-GCM with the precomputed `beforenm` state costs 134 ns at 64 B. Experiment 001, which expands the key on every call, measured 177 ns.
6. **Numbers are consistent with experiment 001.** libsodium ChaCha20-Poly1305 at 1400 B: 1217 ns here vs 1173 ns in 001. The virtual call and counter nonce add nothing measurable.

## Conclusions for the design

- **Default implementation stays libsodium for both algorithms** (registry order). It is better for small packets and forged-packet drops, and it is the one library every node always has. Revisit with target-node data. The M3 `node.conf` `impl.*` keys make the switch a config change, with no rebuild.
- **On x86 with AES-NI, AES-256-GCM is cheaper than ChaCha20-Poly1305 in both libraries.** The *client* offer order decides what gets used. Phones without AES hardware should offer ChaCha first, which is design 01's default.
- Keep `vzeroupper` in any future backend that wraps AVX code from another library.

## Reproduce

```bash
# Any Ubuntu 22.04+ machine (dev box, GCP e2-micro, Oracle A1):
sudo apt-get install -y git cmake g++ libsodium-dev libssl-dev
git clone https://github.com/shivesh1606/Cpp-VPN-Core.git && cd Cpp-VPN-Core
git checkout feature/m2-libsodium        # until merged to master
bash experiments/002-crypto-bench-backends/run.sh \
  | tee experiments/002-crypto-bench-backends/results/$(date +%F)_<host>_<env>.txt

# Variants: BUILD_TYPE= (runbuild.sh flags), CPU=1, COUNT=200000 (shared-core VMs)
# Show the cross-library interference that finding 3 fixed:
./crypto_bench --no-vzeroupper
```

- **WSL2 without root (as here):** unpack `libsodium-dev` with `apt-get download` + `dpkg -x` and pass `PREFIX=<dir>/usr`.
- **e2-micro:** a shared-core VM with burst credits. Run `COUNT=200000` a few times and keep all files; expect a large spread.

## Deferred runs

| Host | Why it matters | Status |
|---|---|---|
| GCP e2-micro (x86, shared core) | Current production node | Deferred; run the recipe on the VM |
| Oracle A1 (Ampere Altra, arm64) | Free tier with 10 TB egress (parked P1). libsodium 1.0.18 has no ARM AES-GCM, so only OpenSSL AES and both ChaCha implementations register. | Deferred. Correctness was checked under QEMU emulation (Ubuntu 24.04 arm64): 69/69 tests pass, and the registered backends are chacha20poly1305 (libsodium, openssl), aes256gcm (openssl) and xor. Emulated timings are meaningless and are not recorded. |
