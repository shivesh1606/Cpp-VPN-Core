# Reading Guide

Where to read about every concept used in this repo's code and design docs. Sections:

1. **Current engine in 5 minutes:** how today's code works, with file and line links.
2. **Glossary:** every term used in the design docs, where we use it, and the primary source.
3. **Reading paths:** ordered lists of what to read, with the specific sections, per goal.

Primary sources (RFCs, specs, official docs) come first. Books and blogs are marked as secondary.

---

## 1. Current engine in 5 minutes (protocols v1 and v2)

```
main()  main.cpp:546
  setup     --config / node.conf -> NodeConfig; node key; allowed_clients or tickets (config/, auth/)
            TunDevice::create (+ configure from tun_cidr), UDP socket(port), ClientManager (IP pool)
            v2::Server if the node has a key (protocol/v2/Server.cpp); defaults = v1 only
  loop      main.cpp:700  select(sock, tun, 1 s timeout)
  |-- every second   stats; v2 tick + revocation poll (design 03)        main.cpp:723
  |                  v1: expire pending HELLOs (10 s), sweep idle clients (60 s)
  |-- UDP readable   recvmmsg x8  main.cpp:773
  |     first byte 0x20 -> v2::Server::receive                                main.cpp:795
  |         HS_INIT  -> design 02 section 5 pipeline -> HS_RESP (sendto)
  |         ACK / DATA / KEEPALIVE / BYE -> replay window, open(), roaming; DATA -> write(tun)
  |     else (v1, if accept_v1)
  |         DATA     -> handleUdpToTun  main.cpp:53   lookup ip:port / session_id, XorLock, write(tun)
  |         other    -> handleHandshake main.cpp:120  HELLO / ACK / BYE / KEEPALIVE
  `-- TUN readable   read() -> IPv4 destination                                main.cpp:876
        v2 session owns it -> v2::Server::seal                                main.cpp:900
        else v1 client     -> XorLock seal
        -> sendmmsg x3 batch                                                  main.cpp:969
```

| Component | File | What to read in it |
|---|---|---|
| Event loop, packet dispatch | [main.cpp](../main.cpp) | `main()` loop, `handleUdpToTun`, `handleHandshake` |
| Wire format v1 | [protocol/Handshake.h](../protocol/Handshake.h) | `PacketHeader` (5 B), packet structs |
| Connected clients, IP pool, roaming | [sessions/client/Client_Manager.h](../sessions/client/Client_Manager.h), [.cpp](../sessions/client/Client_Manager.cpp) | The three maps, `freeIp`, `updateClientEndpoint`, `sweepDeadClients` |
| Pending handshakes | [sessions/session/ClientSession.h](../sessions/session/ClientSession.h), [.cpp](../sessions/session/ClientSession.cpp) | `SessionState`, `eraseExpiredSessions` |
| Key exchange (placeholder) | [crypto/DiffieHellman.h](../crypto/DiffieHellman.h) | `P=127` toy DH; why it's insecure: design 01 §1, design 02 |
| Cipher layer (pluggable) | [crypto/SessionLock.h](../crypto/SessionLock.h), [crypto/CipherRegistry.cpp](../crypto/CipherRegistry.cpp), [crypto/backends/](../crypto/backends/) | `SessionLock::seal/open`, registry order, `XorBackend` (the v1 wire; insecure), and `AeadLock<P>` with the libsodium and OpenSSL primitives (built and tested; on the wire from M4). Design 01 §2.2 |
| Tickets (M5) | [auth/](../auth/), [tools/vpnctl.cpp](../tools/vpnctl.cpp) | `Ticket::verify` (design 03 §2.1), `RevocationList`, `RevocationFetcher`, `TicketAuthenticator` (the v2 server's step-5 hook), `Bundle`, `IssuerKey`; design 03 §9 |
| Protocol v2 (M4) | [protocol/noise/Noise.h](../protocol/noise/Noise.h), [protocol/v2/](../protocol/v2/), [tools/vpn_client_v2.cpp](../tools/vpn_client_v2.cpp) | Noise IK; wire layouts; `Server` (responder, sessions, timers, drop counters); `Client` (initiator, also used by the Windows client); design 02 §11 |
| Node config and identity (M3) | [config/](../config/), [crypto/NodeIdentity.h](../crypto/NodeIdentity.h), [deploy/node.conf.example](../deploy/node.conf.example) | INI parser, `NodeConfig` validation, CLI (`--config`, `--set`, `--check-config`, `--gen-key`); plan Discussion 4a |
| Tests and benchmark | [tests/README.md](../tests/README.md), [tools/crypto_bench.cpp](../tools/crypto_bench.cpp) | GoogleTest layout and KATs; `crypto_bench` (experiment 002) |
| TUN device | [net/tun/TunDevice.cpp](../net/tun/TunDevice.cpp) | `IFF_TUN | IFF_NO_PI`, `TUNSETIFF` |
| Stats and profiling | [utils/counter_definition.h](../utils/counter_definition.h), [utils/profiling.h](../utils/profiling.h) | `print_Stats`, `PROFILE_SCOPE_*`, `RDTSC()` |
| Logger | [utils/logger.cpp](../utils/logger.cpp) | 64 KB buffer, flushed by the stats print |
| Windows test client | [clients/windows/README.md](../clients/windows/README.md) | `--probe`, tunnel mode |

---

## 2. Glossary

| Term | Meaning, in one line | Where we use it | Primary reference |
|---|---|---|---|
| **TUN device** | Virtual network interface that hands IP packets to a userspace program | [net/tun/TunDevice.cpp](../net/tun/TunDevice.cpp) | [Linux kernel: Universal TUN/TAP driver](https://docs.kernel.org/networking/tuntap.html) |
| **Wintun** | TUN driver for Windows (by WireGuard) | [clients/windows](../clients/windows/README.md) | [wintun.net](https://www.wintun.net/) |
| **recvmmsg / sendmmsg** | Receive or send many UDP datagrams in one syscall | [main.cpp](../main.cpp) loop | [recvmmsg(2)](https://man7.org/linux/man-pages/man2/recvmmsg.2.html), [sendmmsg(2)](https://man7.org/linux/man-pages/man2/sendmmsg.2.html) |
| **MTU** | Largest packet a link carries; tunnel headers reduce the inner MTU | Design 01 §3 (1442 → 1420) | [RFC 8899 §1 (PMTU background)](https://www.rfc-editor.org/rfc/rfc8899#section-1) |
| **NAT / MASQUERADE** | Server rewrites client traffic to its own public IP | Plan P1 (deployment) | [Arch Wiki: Internet sharing](https://wiki.archlinux.org/title/Internet_sharing) |
| **Roaming** | Client keeps its session when its IP or port changes | Design 02 §6 | [WireGuard whitepaper §2.1 (endpoints)](https://www.wireguard.com/papers/wireguard.pdf) |
| **Symmetric cipher** | Same key encrypts and decrypts | Design 01 | [Crypto 101, ch. "Stream ciphers"](https://www.crypto101.io/) (secondary) |
| **Single-byte XOR weakness** | 256 possible keys, so brute force is trivial | Design 01 §1 | [Cryptopals set 1, challenge 3](https://cryptopals.com/sets/1/challenges/3) (hands-on) |
| **AEAD** | Authenticated encryption with associated data: secrecy plus a tamper-proof tag | Design 01 §2 | [RFC 5116](https://www.rfc-editor.org/rfc/rfc5116), [libsodium: AEAD](https://doc.libsodium.org/secret-key_cryptography/aead) |
| **ChaCha20-Poly1305** | AEAD built from the ChaCha20 stream cipher and the Poly1305 MAC | Design 01 (`cipher_id` 1) | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) |
| **AES-256-GCM** | AEAD built on AES; fast with AES-NI hardware | Design 01 (`cipher_id` 2), experiment 001 | [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final), [libsodium AES-GCM](https://doc.libsodium.org/secret-key_cryptography/aead/aes-256-gcm) |
| **Nonce** | Number used once per key; here, the packet counter | Design 01 C1 | [RFC 8439 §4 (security considerations)](https://www.rfc-editor.org/rfc/rfc8439#section-4) |
| **AAD** | Data that's authenticated but not encrypted (our header) | Design 01 C2 | [RFC 5116 §2.1](https://www.rfc-editor.org/rfc/rfc5116#section-2.1) |
| **Tag** | The 16-byte authenticator AEAD appends; forged packets fail it | Design 01, experiment 001 ("forged → drop") | [RFC 8439 §2.5 (Poly1305)](https://www.rfc-editor.org/rfc/rfc8439#section-2.5) |
| **KAT** (known-answer test) | Test against published input/output vectors | Design 01 C5, design 02 §10 | [RFC 8439 §2.8.2](https://www.rfc-editor.org/rfc/rfc8439#section-2.8.2) (example vector) |
| **Key usage limits** | Maximum data per key before rekeying | Design 01 C4 | [RFC 8446 §5.5](https://www.rfc-editor.org/rfc/rfc8446#section-5.5) |
| **Diffie-Hellman (DH)** | Two parties derive a shared secret over a public channel | Today: `P=127` toy; v2: X25519 | [Boneh–Shoup, ch. 10](https://toc.cryptobook.us/) (secondary, free) |
| **X25519** | Modern elliptic-curve DH (Curve25519) | Design 02 | [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748), [libsodium scalarmult](https://doc.libsodium.org/advanced/scalar_multiplication) |
| **Ed25519** | Modern digital signature scheme | Design 03 (ticket `sig`) | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), [libsodium signatures](https://doc.libsodium.org/public-key_cryptography/public-key_signatures) |
| **Static vs ephemeral key** | Long-term identity key vs per-handshake throwaway key | Design 02 §2 (key hierarchy) | [Noise spec §7 (handshake patterns)](https://noiseprotocol.org/noise.html#handshake-patterns) |
| **Forward secrecy** | Leaking long-term keys later doesn't expose past traffic | Design 02 G3 (`ee`) | [Noise spec §7.7 (payload security properties)](https://noiseprotocol.org/noise.html) |
| **BLAKE2b** | Fast hash function; our Noise hash | Design 02 D1 | [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693), [libsodium generic hashing](https://doc.libsodium.org/hashing/generic_hashing) |
| **HMAC / HKDF** | Keyed hash / key derivation from DH outputs | Design 02 §2 | [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104), [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869), [Noise §4.3](https://noiseprotocol.org/noise.html#hash-functions) |
| **Noise Protocol Framework** | Recipe book for building authenticated key exchanges | Design 02 | [Noise spec (rev 34)](https://noiseprotocol.org/noise.html) |
| **Noise IK** | Pattern: initiator knows the responder's static key; 1-RTT; hides the initiator's identity | Design 02 §2 | [Noise §7.5 (interactive patterns)](https://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental), [Noise Explorer: IK](https://noiseexplorer.com/patterns/IK/) (annotated, interactive) |
| **es / ss / ee / se** | The four DH operations in IK, each adding a security property | Design 02 §2 | [Noise §5.3 (HandshakeState)](https://noiseprotocol.org/noise.html#the-handshakestate-object) |
| **Split()** | Final Noise step that outputs the two transport keys | Design 02 §2 (`k_c2s`, `k_s2c`) | [Noise §5.2 (SymmetricState)](https://noiseprotocol.org/noise.html#the-symmetricstate-object) |
| **mac1 / mac2, cookie** | Cheap pre-checks that drop scanners and floods before any DH | Design 02 §3.3, D2 | [WireGuard whitepaper §5.4.4–5.4.7](https://www.wireguard.com/papers/wireguard.pdf) |
| **TAI64N** | 12-byte timestamp; replay protection for msg1 | Design 02 G6 | [TAI64 format](https://cr.yp.to/libtai/tai64.html) |
| **Replay window** | Sliding bitmap that rejects duplicate or old counters | Design 01 C6, design 02 §6 | [RFC 6479](https://www.rfc-editor.org/rfc/rfc6479) |
| **Rekey** | New handshake every 120 s; fresh keys | Design 02 §7 | [WireGuard whitepaper §6 (timers)](https://www.wireguard.com/papers/wireguard.pdf) |
| **Node key, `S_pub`** | The node's static X25519 key pair; clients pin the public half | [crypto/NodeIdentity.h](../crypto/NodeIdentity.h), `vpn_server --gen-key` (plan N1) | [RFC 7748 §6.1](https://www.rfc-editor.org/rfc/rfc7748#section-6.1), [Noise §7 (static keys)](https://noiseprotocol.org/noise.html#handshake-patterns) |
| **base64url** | URL-safe base64 without padding, used for keys in files and configs | Node key file, `issuer_pk.N` | [RFC 4648 §5](https://www.rfc-editor.org/rfc/rfc4648#section-5) |
| **CIDR, pool** | `10.8.0.1/24`: tun0 address plus prefix; clients get server+1 … broadcast−1 | [net/ip/Cidr.h](../net/ip/Cidr.h), `tun_cidr` (plan N5) | [RFC 4632 §3.1](https://www.rfc-editor.org/rfc/rfc4632#section-3.1) |
| **SIOCSIFADDR / SIOCSIFFLAGS** | ioctls that set an interface address and bring it up (what `ip addr`/`ip link` do) | `TunDevice::configure` | [netdevice(7)](https://man7.org/linux/man-pages/man7/netdevice.7.html) |
| **Allowlist (`allowed_clients`)** | File of client public keys a v2 node accepts (`auth.mode = allowlist`) | [deploy/node.conf.example](../deploy/node.conf.example), design 02 §7 | (concept as in WireGuard `AllowedIPs`/peer lists: [WireGuard: cryptokey routing](https://www.wireguard.com/#cryptokey-routing)) |
| **Handshake ID (`hsid`)** | First 8 bytes of the final Noise handshake hash; logged by client and server | design 02 §8 | [Noise §5.2 (handshake hash)](https://noiseprotocol.org/noise.html#the-symmetricstate-object) |
| **receiver_idx** | Random 32-bit routing index in every packet, replacing the sequential session ID | Design 02 §3 | [WireGuard whitepaper §5.4.2 (sender index)](https://www.wireguard.com/papers/wireguard.pdf) |
| **Control plane / data plane** | Who decides access vs who forwards packets | Design docs README, design 03 §1 | [WireGuard: conceptual overview](https://www.wireguard.com/#conceptual-overview) (data-plane-only model, for contrast) |
| **Ticket / issuer** | Signed access grant / the party holding the signing key | Design 03, [auth/Ticket.h](../auth/Ticket.h), [tools/vpnctl.cpp](../tools/vpnctl.cpp) | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) (signatures); compare with [RFC 7519 JWT](https://www.rfc-editor.org/rfc/rfc7519) |
| **Revocation list** | Signed list of banned ticket or user IDs, polled by nodes | Design 03 §6, [auth/RevocationList.h](../auth/RevocationList.h) | (Concept as in X.509 CRLs: [RFC 5280 §5](https://www.rfc-editor.org/rfc/rfc5280#section-5), secondary) |
| **Bundle** | QR or base64url blob: nodes + device key + ticket | Design 03 §5, [auth/Bundle.h](../auth/Bundle.h), `--bundle` | [RFC 4648 §5 (base64url)](https://www.rfc-editor.org/rfc/rfc4648#section-5) |
| **Argon2id** | Password hash used to encrypt the issuer key file | Design 03 §4 | [libsodium password hashing](https://doc.libsodium.org/password_hashing/default_phf) |
| **Android Keystore** | Hardware-backed key storage on the phone | Design 03 §5 | [Android Keystore system](https://developer.android.com/privacy-and-security/keystore) |
| **Google ID token** | JWT proving a Google sign-in (Phase 1 issuer) | Design 03 §7, parked P2 | [Verify an ID token on your backend](https://developers.google.com/identity/sign-in/android/backend-auth) |
| **TSC / RDTSC** | CPU timestamp counter used by our profiling | [utils/profiling.h](../utils/profiling.h), experiment 001 | [Intel SDM vol. 3, "Time-Stamp Counter" section](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) |

---

## 3. Reading paths

Suggested order with time estimates. Each step names the section to read, not the whole document.

### Path A — Understand today's engine (≈ 1–2 h)

1. §1 above, then [main.cpp](../main.cpp) top to bottom, with the diagram open.
2. [Linux TUN/TAP driver](https://docs.kernel.org/networking/tuntap.html): sections 1–3.
3. [recvmmsg(2)](https://man7.org/linux/man-pages/man2/recvmmsg.2.html) and [sendmmsg(2)](https://man7.org/linux/man-pages/man2/sendmmsg.2.html): DESCRIPTION and RETURN VALUE.
4. Cloudflare blog, ["How to receive a million packets per second"](https://blog.cloudflare.com/how-to-receive-a-million-packets/) (secondary): why batching and `SO_REUSEPORT` matter (parked P9).
5. Run the [Windows test client](../clients/windows/README.md) `--probe` against the Docker server and follow the server log.

### Path B — Why the current crypto must go (≈ 1 h)

1. [Design 01 §1](design/01-cipher-layer.md) (the problems, with code links).
2. [Cryptopals set 1, challenges 1–3](https://cryptopals.com/sets/1): break single-byte XOR yourself in about 20 lines.
3. [libsodium: AEAD overview](https://doc.libsodium.org/secret-key_cryptography/aead): "Authenticated encryption with additional data" and the comparison table.
4. [RFC 8439 §1–2.1 and §2.8](https://www.rfc-editor.org/rfc/rfc8439): what ChaCha20-Poly1305 does, and an AEAD test vector.
5. [Experiment 001](../experiments/001-crypto-per-packet-cost/README.md): what it costs per packet.

### Path C — The v2 handshake (≈ 3–4 h)

1. [WireGuard whitepaper](https://www.wireguard.com/papers/wireguard.pdf) §1–2 (design goals), §5.4 (handshake), §6 (timers). It's the closest real system to our design.
2. [Noise Explorer: IK pattern](https://noiseexplorer.com/patterns/IK/): read the annotated messages and what each token (`e, es, s, ss`) gives you.
3. [Noise spec](https://noiseprotocol.org/noise.html) §5 (processing rules), §7.5 (IK), §4.3 (HKDF), §12.3 (ChaChaPoly nonce).
4. [RFC 7748 §1, §5–6](https://www.rfc-editor.org/rfc/rfc7748) (X25519).
5. [Design 02](design/02-handshake.md), side by side with the above: §2 (key schedule), §5 (processing order), §6 (state machine).
6. [RFC 6479 §1–2](https://www.rfc-editor.org/rfc/rfc6479): the replay window.

### Path D — Tickets and access control (≈ 1–2 h)

1. [RFC 8032 §1, §5.1](https://www.rfc-editor.org/rfc/rfc8032) (Ed25519) and [libsodium signatures](https://doc.libsodium.org/public-key_cryptography/public-key_signatures): detached mode.
2. [Design 03](design/03-tickets.md) §1–2 (trust model, layout, verification), then §5–6 (vpnctl, bundle, revocation).
3. For contrast: [RFC 7519 §1–3](https://www.rfc-editor.org/rfc/rfc7519). JWT is the common text format; we use a fixed binary format to keep HELLO small and parsing simple.
4. Phase 1 preview (parked P2): [Verify a Google ID token](https://developers.google.com/identity/sign-in/android/backend-auth).

### Path E — Windows client internals (≈ 1 h)

1. [Wintun: usage](https://www.wintun.net/) (session API, ring buffers).
2. Microsoft IP Helper: [CreateUnicastIpAddressEntry](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createunicastipaddressentry) and [CreateIpForwardEntry](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-createipforwardentry): how the client sets the IP and routes.
3. [clients/windows/main.cpp](../clients/windows/main.cpp): `setupRoutes` (split default route `0/1 + 128/1`, server host route) and `runTunnel`.

### Books (secondary, optional depth)

- J.-P. Aumasson, *Serious Cryptography*, 2nd ed., No Starch Press (2024): chapters on stream ciphers, authenticated encryption, Diffie-Hellman and elliptic curves.
- D. Boneh & V. Shoup, *A Graduate Course in Applied Cryptography*: free at [toc.cryptobook.us](https://toc.cryptobook.us/). Chapters 9 (AEAD) and 21 (key exchange).
- [Crypto 101](https://www.crypto101.io/) by L. Van Houtven: free, introductory.

---

## Where each design doc fits

| Our doc | Read first (paths) |
|---|---|
| [01 Cipher layer](design/01-cipher-layer.md) | B |
| [02 Handshake](design/02-handshake.md) | B, then C |
| [03 Tickets](design/03-tickets.md) | C, then D |
| [Implementation plan](plan/implementation-plan.md) | A (to map tasks onto code) |
| [Experiment 001](../experiments/001-crypto-per-packet-cost/README.md) | B |
| [Windows client](../clients/windows/README.md) | A, E |
