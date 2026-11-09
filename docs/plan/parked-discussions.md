# Parked Discussions

Topics raised but deliberately deferred, because they don't block the [implementation plan](implementation-plan.md) (M0–M7). Each entry records the context so far and the trigger for revisiting it. When a topic is picked up, it becomes a design doc in [docs/design/](../design/README.md) and is struck through here.

| # | Topic | Revisit when | Related |
|---|---|---|---|
| P1 | Multi-node deployment (rest of design 04) | Before the second node is deployed | Design 03 §1, plan M3 |
| P2 | Phase 1 serverless issuer | More users than can be handled by hand, or untrusted users (Play Store) | Design 03 §7 |
| P3 | mac2 cookie DoS mechanism | Experiment 004 shows handshake CPU saturation, or before a public launch | Design 02 D2, §3.3 |
| P4 | Monetization: tier enforcement, payments, device limits, quotas | Only if the project shows traction | Design 03 (`tier`, tags) |
| P5 | Windows client GUI | When the CLI test client isn't enough | `clients/windows/` |
| P6 | Server-pushed client settings (DNS, routes, MTU) | When a node needs its own DNS or routes. After M6 the Android app still hardcodes DNS `8.8.8.8`, MTU 1420 and a /32 address; msg2 carries only the tunnel IP, cipher and keepalive | Design 02 msg2 payload |
| P7 | IPv6 (inner and outer) | After M7 | — |
| P8 | Post-quantum hedge (Noise `IKpsk2`) | After M7 | Design 02 |
| P9 | Engine scaling: `epoll`, `SO_REUSEPORT` multi-threading, `io_uring`, live config reload | When one core saturates on a node (experiment 002/003) | README performance goals |
| P10 | Logging, privacy and abuse policy | Before any non-friend users | Design 03 (`user_id` mapping) |
| P11 | Android sign-in API migration (`GoogleSignIn` → Credential Manager) | With P2 | Android `ProfileFragment.kt` |
| P12 | `vpnctl` issuer-key rotation command and multi-admin use | Before the first planned key rotation, or a second person issues tickets | Design 03 §4, §9 |

## P1 — Multi-node deployment

Context gathered so far:
- **Build:** today's build and deploy is `build.ps1` (Docker build on the laptop, `scp` to one GCP VM, restart the `vpn-server` systemd unit). Terraform lives in a separate repo, `vpn-infra`.
- **Proposed pipeline:**
  - GitHub Actions builds `x86_64` and `arm64` static binaries per tag and publishes them as Releases;
  - nodes bootstrap with cloud-init: download the pinned version, write `node.conf`, run `--gen-key`, set up NAT and systemd;
  - Terraform `for_each` over a node map;
  - a node registry (id, host, port, `S_pub`, region, tags), optionally with a health heartbeat for "auto" server selection.
- **Cost (verify current numbers when revisiting):**
  - the dominant cost is egress, not compute;
  - the GCP free tier includes about 1 GB/month of egress;
  - Oracle Always Free includes about 10 TB/month on Ampere A1 (arm64), but only in the home region, and idle instances may be reclaimed.
- **Open questions:**
  - provider mix;
  - arm64 CI (QEMU or native runners). Finding from M2 (2026-11-08): under Docker Desktop's QEMU, Ubuntu 22.04 arm64 crashes in `ldconfig` while installing packages. Ubuntu 24.04 arm64 works (69/69 tests). So QEMU CI needs a 24.04 base, or native arm64 runners;
  - the registry's home (vpnctl file in Phase 0, issuer DB in Phase 1);
  - how bundles learn about new nodes.

## P2 — Phase 1 serverless issuer

- **Proposed stack:** Cloudflare Workers + D1 (free tier). Google ID token verification (JWKS; `aud` = Android web client ID, already requested in `ProfileFragment.kt`). `user_id` mapped from `sub`, grants (tag, expiry, source = invite/admin/purchase), invite codes. Tickets valid 12–24 h, refreshed by the app.
- **Avoid:** free tiers that pause when idle (e.g. Supabase free projects) for an always-on login path.
- **Open questions:** admin tooling, rate limiting, abuse controls, account deletion.

## P3 — mac2 cookie mechanism

- **Context:** the 16-byte field is already reserved and zero-filled. The WireGuard cookie design (whitepaper §5.4.7) is the reference.
- **Open questions:** load-detection trigger, cookie secret rotation (about 2 min), per-IP rate limits.

## P4 — Monetization

- **What exists:** ticket `tier` byte and tags with expiry (design 03).
- **Future work:** a payment webhook (e.g. Google Play Billing real-time notifications) writes grants; nodes map `tier` to limits.
- **Open questions:** concurrent-device limits need cross-node state (heartbeats), and usage quotas need per-session byte counters reported by nodes.

## P5–P11

Placeholders. See the table above for the triggers. Add context here when a topic comes up.
