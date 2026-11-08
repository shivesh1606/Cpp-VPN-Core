// XorBackend.h - Protocol v1 single-byte XOR behind the SessionLock interface.
//
// INSECURE (design doc 01, section 1): no integrity, 256-value keyspace. It exists only for
// protocol v1 compatibility (until milestone M7) and as a benchmark baseline.
// Wire behaviour is byte-identical to the former XorCipher::crypt: out[i] = in[i] ^ key[0].
#ifndef CRYPTO_BACKENDS_XORBACKEND_H
#define CRYPTO_BACKENDS_XORBACKEND_H

#include "crypto/SessionLock.h"

namespace crypto
{

class XorLock final : public SessionLock
{
public:
    explicit XorLock(uint8_t key_byte) : key_(key_byte) {}

    size_t overhead() const override { return 0; }
    void seal(uint64_t counter, const uint8_t *aad, size_t aad_len,
              const uint8_t *in, size_t len, uint8_t *out) override;
    bool open(uint64_t counter, const uint8_t *aad, size_t aad_len,
              const uint8_t *in, size_t len, uint8_t *out) override;

    uint8_t keyByte() const { return key_; }

private:
    uint8_t key_;
};

class XorBackend final : public CipherBackend
{
public:
    uint8_t algorithmId() const override { return kCipherXor; }
    const char *algorithmName() const override { return "xor"; }
    const char *implName() const override { return "builtin"; }
    bool insecure() const override { return true; }

    // Uses key[0] as the XOR byte; the remaining 31 bytes are ignored.
    std::unique_ptr<SessionLock> newLock(const uint8_t key[kKeyBytes]) const override;
};

// Expands a protocol v1 one-byte key into the 32-byte key format (key[0] = byte, rest 0).
void expandV1XorKey(uint8_t xor_key, uint8_t out[kKeyBytes]);

} // namespace crypto

#endif // CRYPTO_BACKENDS_XORBACKEND_H
