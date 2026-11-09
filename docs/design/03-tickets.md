# 03 — Access Tickets and Issuer

| | |
|---|---|
| **Status** | Accepted (2026-11-08) |
| **Scope** | Authorization of clients to nodes: ticket format, issuance (Phase 0 CLI, Phase 1 serverless), verification, revocation, issuer key lifecycle, Phase 0 bundle |
| **Used by** | [02 — Handshake](02-handshake.md) §5 step 5 (`auth_mode = ticket`) |
| **Replaces** | The interim v2 allowlist (`auth.mode = allowlist`, M4: a static list of client keys per node). Protocol v1 still accepts any client that reaches UDP 5555 ([main.cpp:124-205](../../main.cpp#L124-L205)) |

## Decisions

| ID | Decision | Rationale |
|---|---|---|
| T1 | Phase 0: `vpnctl` generates the device key pair and puts `device_sk` in the bundle. Phase 1: the app generates its own key and sends only `device_pk` to the issuer. | One-scan onboarding for a small, trusted user set. The bundle is treated as a secret. |
| T2 | Scope is a `u32` tag bitmask; tag names map to bits in a shared `tags.conf` | One AND per check; adding a node needs no ticket reissue |
| T3 | Phase 0 revocation list is hosted as a raw file in a public GitHub repo or gist | Free. Contents are random IDs only, no personal data. Integrity comes from the signature, not from the host. |
| T4 | `vpnctl` is written in C++ in this repo (CMake target) and shares `Ticket` encode/verify with the node | One implementation of the format, so issuer and node can't diverge |

## 1. Trust model

```
             ISSUE (control plane)                        VERIFY (data plane, offline)
 ┌──────────────────────────────────┐            ┌──────────────────────────────────────────┐
 │ issuer_sk[key_id] (Ed25519)      │            │ node.conf: issuer_pk{key_id → pk},       │
 │ inputs: user_id, device_pk,      │  ticket    │            tags (→ node_mask)            │
 │         tags, tier, lifetime     │──────────▶ │ HS_INIT step 5 (doc 02 §5):              │
 │ P0: vpnctl (laptop)              │ (bundle or │  sig ✓  nbf ≤ now < exp ✓                │
 │ P1: serverless issuer            │  HTTPS)    │  tags & node_mask ≠ 0 ✓                  │
 └───────────────┬──────────────────┘            │  device_pk == s_c ✓   not revoked ✓      │
                 │ signed revocation list        └───────────────▲──────────────────────────┘
                 └──────────── poll every 5 min ─────────────────┘
```

- The only state shared between issuer and nodes is the issuer's public key(s).
- A node never contacts the issuer during a handshake.
- A compromised node yields only that node's static key. It can't mint tickets.

## 2. Ticket v1 (136 B)

```
 0     1        2      3      4             20               52          56        60        64             72                 136
 ┌─────┬────────┬──────┬──────┬─────────────┬────────────────┬───────────┬─────────┬─────────┬──────────────┬──────────────────┐
 │ ver │ key_id │ tier │ rsvd │ user_id     │ device_pk      │ tags      │ nbf     │ exp     │ ticket_id    │ sig              │
 │ u8  │ u8     │ u8   │ u8=0 │ 16 B random │ 32 B X25519    │ u32 mask  │ u32 unix│ u32 unix│ u64 random   │ 64 B Ed25519     │
 └─────┴────────┴──────┴──────┴─────────────┴────────────────┴───────────┴─────────┴─────────┴──────────────┴──────────────────┘
 Integers little-endian.
 sig = crypto_sign_detached(issuer_sk[key_id], "cppvpn-ticket-v1" ‖ bytes[0:72])     (domain separation)
```

| Field | Semantics |
|---|---|
| `ver` | 1. Unknown versions are rejected. |
| `key_id` | Selects `issuer_pk` on the node (rotation, §4) |
| `tier` | Reserved for monetization. A node may later map tier → limits in `node.conf`; ignored for now. |
| `user_id` | Opaque random 128-bit ID, never an email address. The issuer holds the identity mapping. |
| `device_pk` | Must equal the Noise initiator static key `s_c` (binds the ticket to a device) |
| `tags` | Bit *i* set ⇒ the ticket is valid on nodes carrying tag *i* (`tags.conf`) |
| `nbf`, `exp` | Validity window (u32 seconds; valid until 2106). Nodes allow ±60 s clock skew. |
| `ticket_id` | Revocation handle; log correlation |

### 2.1 Verification (`TicketVerifier::verify(ticket, s_c, node)`)

Each failure maps to the doc 02 drop counter `HS_DROP_AUTH_<reason>`.

```
len == 136 && ver == 1 ............................. ✗ AUTH_FORMAT
pk = issuer_pk[key_id] exists ...................... ✗ AUTH_UNKNOWN_KEY
crypto_sign_verify_detached(sig, ctx ‖ bytes[0:72], pk) ✗ AUTH_SIG
nbf − 60 ≤ now < exp + 60 .......................... ✗ AUTH_EXPIRED
tags & node_mask ≠ 0 ............................... ✗ AUTH_SCOPE
device_pk == s_c (crypto_verify_32) ................ ✗ AUTH_DEVICE
ticket_id ∉ revoked && user_id ∉ revoked ........... ✗ AUTH_REVOKED
```

### 2.2 Interaction with active sessions

- The ticket is presented again on every rekey (120 s, doc 02 §6). An expired ticket therefore ends the session within `REJECT_AFTER` (180 s).
- A session stores `user_id` and `ticket_id`. On a revocation-list update, the node drops matching ACTIVE sessions immediately.

## 3. Tag registry (`tags.conf`)

```ini
# bit = name   (shared by vpnctl / issuer and nodes; bits are never reused)
0 = friends
1 = free
2 = premium
8 = region-in
9 = region-us
```

Node config: `tags = friends, region-in`. At startup the node computes `node_mask` from these names.

## 4. Issuer key lifecycle

```
gen key_id=N+1 ──▶ add issuer_pk[N+1] to all nodes ──▶ issue with N+1 ──▶ wait max ticket lifetime ──▶ remove issuer_pk[N]
```

| Phase | `issuer_sk` storage |
|---|---|
| P0 | Laptop file, passphrase-encrypted: `crypto_pwhash` (Argon2id) → key → `crypto_secretbox`. Mode 0600, with an offline backup. |
| P1 | Secret in the serverless issuer's environment; never returned by any endpoint |

## 5. Phase 0: `vpnctl` and the bundle

```
vpnctl init                                   → issuer.key (encrypted sk), issuer.pub, key_id
vpnctl node add --id in-1 --host H --port P --pub S_pub --tags friends,region-in
vpnctl issue --user alice --tags friends --days 30
   ├─ user_id = random(16)   (stored in users.json: alice → user_id)
   ├─ device keypair (X25519)                       ← T1 (A)
   ├─ ticket (§2), signed
   └─ bundle → base64url → QR (terminal + PNG)
vpnctl revoke --user alice | --ticket <id>    → revocations.bin (seq+1, signed) → push to GitHub (T3)
```

Bundle v1:

```
cppvpn://import?b=<base64url(bundle)>
bundle = { ver u8, node_count u8, nodes[ {node_id, host, port u16, S_pub 32, tags u32} ],
           device_sk 32, ticket 136 }
~230 B for one node → ~310 base64url chars; QR byte-mode capacity ≈ 2.9 KB → about 10 nodes
```

- On import, the app stores `device_sk` wrapped with an Android Keystore AES-GCM key.
- The bundle is a secret: share it only over a private channel.

## 6. Revocation list

```
┌─────┬────────┬──────────┬───────────────┬───────────┬───────────────────────────────────────┬─────────┐
│ ver │ key_id │ seq u64  │ issued_at u32 │ count u32 │ entries[count]: {kind u8, id 16 B}     │ sig 64  │
└─────┴────────┴──────────┴───────────────┴───────────┴───────────────────────────────────────┴─────────┘
kind: 1 = user_id, 2 = ticket_id (zero-padded to 16 B)
sig = Ed25519(issuer_sk, "cppvpn-revocation-v1" ‖ body)
```

- Nodes poll `revocation_url` every 5 minutes.
- A list is accepted only if its signature is valid and `seq` is greater than the current one (no rollback).
- On fetch failure, the node keeps the last good list.
- Worst-case revocation delay is the minimum of the poll interval and the ticket's `exp`.

## 7. Phase 1: serverless issuer (outline; detailed in a later doc)

```
App ──Google Sign-In──▶ id_token (JWT)
App ──POST /v1/tickets {node_id, device_pk}, Authorization: Bearer id_token──▶ Issuer
Issuer: verify JWT (Google JWKS; aud, iss, exp) → user_id ← sub mapping
        grants(user_id) → tags, tier → sign ticket (exp 12–24 h)
App ◀── {nodes[], ticket} ──     device_sk never leaves the phone
```

Ticket format and node verification are identical to Phase 0. Only the issuer changes.

## 8. Code impact

| New | Purpose |
|---|---|
| `auth/Ticket.{h,cpp}` | Encode/decode/verify (shared by node and `vpnctl`) |
| `auth/RevocationList.{h,cpp}` | Parse, verify, monotonic `seq`, lookup set |
| `auth/RevocationFetcher` | Periodic HTTPS GET, run off the packet loop (separate thread or forked helper; must not block `select()`) |
| `tools/vpnctl/` | CLI target (§5) |
| `node.conf` | `issuer_pk.<key_id>`, `tags`, `revocation_url`, `auth_mode = ticket` |
| Android | QR import (`cppvpn://` deep link), Keystore-wrapped `device_sk`, ticket in `HS_INIT` payload |

## References

- [RFC 8032 — Ed25519][rfc8032] · [libsodium public-key signatures][sodium-sign]
- [libsodium password hashing (Argon2id)][sodium-pwhash] · [libsodium secretbox][sodium-secretbox]
- [RFC 4648 §5 — base64url][rfc4648]
- [Android Keystore system][android-keystore]
- [Google: verify an ID token on the backend][google-idtoken]
- [RFC 7519 — JSON Web Token][rfc7519]

[rfc8032]: https://www.rfc-editor.org/rfc/rfc8032
[sodium-sign]: https://doc.libsodium.org/public-key_cryptography/public-key_signatures
[sodium-pwhash]: https://doc.libsodium.org/password_hashing/default_phf
[sodium-secretbox]: https://doc.libsodium.org/secret-key_cryptography/secretbox
[rfc4648]: https://www.rfc-editor.org/rfc/rfc4648#section-5
[android-keystore]: https://developer.android.com/privacy-and-security/keystore
[google-idtoken]: https://developers.google.com/identity/sign-in/android/backend-auth
[rfc7519]: https://www.rfc-editor.org/rfc/rfc7519
