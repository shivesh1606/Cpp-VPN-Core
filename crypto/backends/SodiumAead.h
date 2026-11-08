// SodiumAead.h - libsodium AEAD primitives (design doc 01, section 2.1). Wrapped by AeadLock<>.
//
//   SodiumChaCha20Poly1305  cipher_id 1  crypto_aead_chacha20poly1305_ietf_*  (RFC 8439)
//   SodiumAes256Gcm         cipher_id 2  crypto_aead_aes256gcm_*_afternm      (NIST SP 800-38D)
//
// libsodium's AES-256-GCM needs hardware AES (x86 AES-NI + PCLMUL in 1.0.18); it is registered
// only when sodiumAes256GcmAvailable() is true. ARM nodes use the OpenSSL backend or ChaCha20.
#ifndef CRYPTO_BACKENDS_SODIUMAEAD_H
#define CRYPTO_BACKENDS_SODIUMAEAD_H

#include <sodium.h>

#include "crypto/backends/AeadLock.h"

namespace crypto
{

// sodium_init() once (thread-safe, idempotent). False if libsodium cannot initialise.
bool sodiumReady();
// True if this CPU supports libsodium's AES-256-GCM.
bool sodiumAes256GcmAvailable();

class SodiumChaCha20Poly1305
{
public:
    static constexpr uint8_t kId = kCipherChaCha20Poly1305;
    static constexpr const char *kAlgorithm = "chacha20poly1305";
    static constexpr const char *kImpl = "libsodium";

    explicit SodiumChaCha20Poly1305(const uint8_t key[kKeyBytes]);
    ~SodiumChaCha20Poly1305();
    SodiumChaCha20Poly1305(const SodiumChaCha20Poly1305 &) = delete;
    SodiumChaCha20Poly1305 &operator=(const SodiumChaCha20Poly1305 &) = delete;

    void seal(const uint8_t nonce[kNonceBytes], const uint8_t *aad, size_t aad_len,
              const uint8_t *in, size_t len, uint8_t *out);
    bool open(const uint8_t nonce[kNonceBytes], const uint8_t *aad, size_t aad_len,
              const uint8_t *in, size_t len, uint8_t *out);

private:
    uint8_t key_[kKeyBytes];
};

class SodiumAes256Gcm
{
public:
    static constexpr uint8_t kId = kCipherAes256Gcm;
    static constexpr const char *kAlgorithm = "aes256gcm";
    static constexpr const char *kImpl = "libsodium";

    // Expands the AES key schedule once per key (crypto_aead_aes256gcm_beforenm).
    explicit SodiumAes256Gcm(const uint8_t key[kKeyBytes]);
    ~SodiumAes256Gcm();
    SodiumAes256Gcm(const SodiumAes256Gcm &) = delete;
    SodiumAes256Gcm &operator=(const SodiumAes256Gcm &) = delete;

    void seal(const uint8_t nonce[kNonceBytes], const uint8_t *aad, size_t aad_len,
              const uint8_t *in, size_t len, uint8_t *out);
    bool open(const uint8_t nonce[kNonceBytes], const uint8_t *aad, size_t aad_len,
              const uint8_t *in, size_t len, uint8_t *out);

private:
    crypto_aead_aes256gcm_state state_; // CRYPTO_ALIGN(16) in sodium.h
    bool ok_ = false;                   // false if the CPU lacks AES-NI
};

} // namespace crypto

#endif // CRYPTO_BACKENDS_SODIUMAEAD_H
