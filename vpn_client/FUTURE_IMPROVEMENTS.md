# VPN Client Future Improvements

This document captures planned enhancements for the desktop VPN client and related server/protocol work.

## 1. Security and Cryptography

- Replace the custom XOR stream cipher with an authenticated encryption algorithm such as ChaCha20-Poly1305 or AES-256-GCM.
- Replace the current Diffie-Hellman exchange using `P=127` with a modern curve key exchange like X25519 or Curve25519.
- Replace `rand()` with a secure system RNG (`getrandom()`, `/dev/urandom`, or platform equivalent).
- Add a proper key derivation function (HKDF or similar) instead of using a single 8-bit XOR key.
- Add packet authentication and replay protection for all tunnel traffic.

## 2. Client Reliability and Usability

- Add a configuration file and CLI options for server address, port, TUN interface name, and logging.
- Add a startup/teardown wrapper script for Linux that creates the TUN device, adds routes, and cleans up on exit.
- Add reconnect and keepalive behavior so the client can recover from transient network drops.
- Add better error handling and retry logic during the handshake.
- Add configurable log levels, log rotation, and optional file logging.
- Add a dedicated `vpn_client` command wrapper for easier startup.

## 3. Cross-Platform Support

- Add separate TUN/TAP backends for macOS and Windows.
- Abstract platform-specific tunnel creation so the client can be ported beyond Linux.
- Add build support for non-Linux platforms with conditional compilation.

## 4. Protocol and Compatibility

- Add versioning to handshake packets so client/server compatibility can evolve safely.
- Add explicit handshake timeouts and state cleanup on the server and client.
- Add a proper state machine for session establishment instead of a simple one-shot flow.
- Support handshake negotiation for future cryptographic upgrades.

## 5. Testing and Quality

- Add unit tests for:
  - handshake packet serialization/deserialization
  - key derivation and XOR/AES encryption
  - client session state and reconnection logic
- Add integration tests that exercise the full client/server handshake and data path.
- Add static analysis / lint checks for cross-platform C++ compatibility.

## 6. Performance and Scalability

- Add configurable UDP socket tuning (`SO_RCVBUF`, `SO_SNDBUF`, non-blocking I/O) on the client.
- Add packet batching support for high-throughput workloads where applicable.
- Add CPU/memory profiling hooks for the client to monitor tunnel throughput.

## 7. Documentation

- Add a dedicated client README that describes install, build, and run steps.
- Add `vpn_client/FUTURE_IMPROVEMENTS.md` as the living roadmap for client development.
- Add example configuration and startup scripts for Linux.
