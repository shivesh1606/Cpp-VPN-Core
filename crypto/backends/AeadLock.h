// AeadLock.h - Generic SessionLock / CipherBackend for any 96-bit-nonce AEAD (design doc 01).
//
// Every AEAD backend is a small "primitive" class (libsodium, OpenSSL, ...) that only knows how
// to seal/open with an explicit 12-byte nonce. AeadLock<P> adds the parts that must be identical
// for every library, so they are written and tested exactly once:
//   - nonce construction from the packet counter (constraint C1): 0x00000000 || counter_le64
//   - tag size (16 B) and the short-input check in open()
//
// Primitive requirements (checked at compile time by use):
//   static constexpr uint8_t     kId;          // wire cipher_id
//   static constexpr const char *kAlgorithm;   // "chacha20poly1305", "aes256gcm"
//   static constexpr const char *kImpl;        // "libsodium", "openssl"
//   explicit P(const uint8_t key[kKeyBytes]);   // per-key setup; may allocate
//   void seal(const uint8_t nonce[kNonceBytes], const uint8_t *aad, size_t aad_len,
//             const uint8_t *in, size_t len, uint8_t *out);   // out: len + kTagBytes
//   bool open(const uint8_t nonce[kNonceBytes], const uint8_t *aad, size_t aad_len,
//             const uint8_t *in, size_t len, uint8_t *out);   // len >= kTagBytes
// seal/open must not allocate (C3). On an internal library failure seal() zero-fills `out`
// (fail closed: the peer rejects it) and open() returns false.
#ifndef CRYPTO_BACKENDS_AEADLOCK_H
#define CRYPTO_BACKENDS_AEADLOCK_H

#include <cstring>

#include "crypto/SessionLock.h"

namespace crypto
{

constexpr size_t kNonceBytes = 12;
constexpr size_t kTagBytes = 16;

// Constraint C1: 96-bit nonce = 4 zero bytes || 64-bit counter, little-endian (as WireGuard).
// Written byte by byte so the result does not depend on host endianness.
inline void counterNonce(uint64_t counter, uint8_t nonce[kNonceBytes])
{
    nonce[0] = nonce[1] = nonce[2] = nonce[3] = 0;
    for (int i = 0; i < 8; i++)
        nonce[4 + i] = static_cast<uint8_t>(counter >> (8 * i));
}

template <class Primitive>
class AeadLock final : public SessionLock
{
public:
    explicit AeadLock(const uint8_t key[kKeyBytes]) : aead_(key) {}

    size_t overhead() const override { return kTagBytes; }

    void seal(uint64_t counter, const uint8_t *aad, size_t aad_len,
              const uint8_t *in, size_t len, uint8_t *out) override
    {
        uint8_t nonce[kNonceBytes];
        counterNonce(counter, nonce);
        aead_.seal(nonce, aad, aad_len, in, len, out);
    }

    bool open(uint64_t counter, const uint8_t *aad, size_t aad_len,
              const uint8_t *in, size_t len, uint8_t *out) override
    {
        if (len < kTagBytes)
            return false;
        uint8_t nonce[kNonceBytes];
        counterNonce(counter, nonce);
        return aead_.open(nonce, aad, aad_len, in, len, out);
    }

private:
    Primitive aead_;
};

template <class Primitive>
class AeadBackend final : public CipherBackend
{
public:
    uint8_t algorithmId() const override { return Primitive::kId; }
    const char *algorithmName() const override { return Primitive::kAlgorithm; }
    const char *implName() const override { return Primitive::kImpl; }

    std::unique_ptr<SessionLock> newLock(const uint8_t key[kKeyBytes]) const override
    {
        return std::make_unique<AeadLock<Primitive>>(key);
    }
};

} // namespace crypto

#endif // CRYPTO_BACKENDS_AEADLOCK_H
