// SessionLock.h - Pluggable transport cipher interfaces (design doc 01, section 2.2).
//
// A SessionLock is the per-direction, per-session cipher state created right after the
// handshake. A CipherBackend is one (algorithm, implementation) pair that creates locks.
// The packet loop only ever talks to SessionLock, via one virtual call per packet.
#ifndef CRYPTO_SESSIONLOCK_H
#define CRYPTO_SESSIONLOCK_H

#include <cstddef>
#include <cstdint>
#include <memory>

namespace crypto
{

constexpr size_t kKeyBytes = 32;

// Wire cipher_id values (design 01, section 2.1). The id names the ALGORITHM only:
// the same algorithm from different libraries is wire-identical.
enum CipherId : uint8_t
{
    kCipherXor = 0,              // insecure, protocol v1 and benchmark baseline only
    kCipherChaCha20Poly1305 = 1, // RFC 8439 (milestone M2)
    kCipherAes256Gcm = 2,        // NIST SP 800-38D (milestone M2)
};

class SessionLock
{
public:
    virtual ~SessionLock() = default;

    // Bytes seal() appends (authentication tag): 16 for AEAD, 0 for XOR.
    virtual size_t overhead() const = 0;

    // Encrypts `len` bytes of `in` into `out`, which must hold len + overhead() bytes.
    // `counter` is the per-direction packet number (used as the nonce); `aad` is authenticated
    // but not encrypted. Must not allocate (design 01, constraint C3).
    virtual void seal(uint64_t counter, const uint8_t *aad, size_t aad_len,
                      const uint8_t *in, size_t len, uint8_t *out) = 0;

    // Decrypts `len` bytes of `in` (ciphertext + tag) into `out`, which must hold
    // len - overhead() bytes. Returns false if authentication fails (forged, modified,
    // wrong key) or `len` < overhead(). Must not allocate.
    virtual bool open(uint64_t counter, const uint8_t *aad, size_t aad_len,
                      const uint8_t *in, size_t len, uint8_t *out) = 0;
};

class CipherBackend
{
public:
    virtual ~CipherBackend() = default;

    virtual uint8_t algorithmId() const = 0;   // wire cipher_id
    virtual const char *algorithmName() const = 0;
    virtual const char *implName() const = 0;  // "builtin", "libsodium", "openssl"
    virtual bool insecure() const { return false; }

    // Creates a lock bound to `key`. Per-key setup happens here (allocation allowed),
    // never in seal()/open().
    virtual std::unique_ptr<SessionLock> newLock(const uint8_t key[kKeyBytes]) const = 0;
};

} // namespace crypto

#endif // CRYPTO_SESSIONLOCK_H
