# Design Documents

Each document records one design decision: its context, the decision itself, its constraints, and references. The code is the source of truth for current behaviour; these documents describe the agreed target and why.

## Index

| # | Document | Status | Implementation | Summary |
|---|---|---|---|---|
| 01 | [Pluggable transport cipher layer](01-cipher-layer.md) | Accepted (2026-11-08) | M1 + M2 done: interfaces, libsodium/OpenSSL backends, KATs, `crypto_bench`. On the wire in M4 | Replace XOR with AEAD behind `CipherBackend`/`SessionLock`; per-session algorithm negotiation; per-node library choice |
| 02 | [Handshake (protocol v2)](02-handshake.md) | Accepted (2026-11-08) | M4 (not started) | Noise IK on libsodium (BLAKE2b); explicit encrypted ACK with DATA fallback; mac2 reserved; drop-reason counters |
| 03 | [Access tickets and issuer](03-tickets.md) | Accepted (2026-11-08) | M5 (not started) | Ed25519-signed tickets verified offline by nodes; Phase 0 CLI issuer, Phase 1 serverless issuer |
| 04 | Multi-node deployment | 4a accepted (2026-11-08); rest parked | 4a done in M3 (config, identity, tun0); rest parked | Node config and identity (4a: [plan §Discussion 4a](../plan/implementation-plan.md#discussion-4a-node-config-and-identity-correlated-with-m3m4)); release pipeline and registry parked ([P1](../plan/parked-discussions.md#p1--multi-node-deployment)) |

New to these concepts? Start with the [reading guide](../reading-guide.md).

Related: [implementation plan](../plan/implementation-plan.md) · [parked discussions](../plan/parked-discussions.md) · [experiments](../../experiments/README.md)

## Target architecture (summary)

```
 Issuer (vpnctl → serverless) ──signed ticket──▶ Client ◀──UDP, AEAD──▶ VPN node (C++ engine)
        └────────── issuer public key (only shared state) ──────────────────────┘
```
