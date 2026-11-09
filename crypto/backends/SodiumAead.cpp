#include "crypto/backends/SodiumAead.h"

namespace crypto
{

bool sodiumReady()
{
    static const bool ready = sodium_init() >= 0; // 0 = initialised now, 1 = already
    return ready;
}

bool sodiumAes256GcmAvailable()
{
    return sodiumReady() && crypto_aead_aes256gcm_is_available() == 1;
}

// ---------------- ChaCha20-Poly1305 (IETF, 96-bit nonce) ----------------

SodiumChaCha20Poly1305::SodiumChaCha20Poly1305(const uint8_t key[kKeyBytes])
{
    sodiumReady();
    std::memcpy(key_, key, kKeyBytes);
}

SodiumChaCha20Poly1305::~SodiumChaCha20Poly1305()
{
    sodium_memzero(key_, sizeof(key_));
}

void SodiumChaCha20Poly1305::seal(const uint8_t nonce[kNonceBytes], const uint8_t *aad,
                                  size_t aad_len, const uint8_t *in, size_t len, uint8_t *out)
{
    // Combined mode: out = ciphertext || 16-byte tag. Always returns 0.
    crypto_aead_chacha20poly1305_ietf_encrypt(out, nullptr, in, len, aad, aad_len,
                                              nullptr, nonce, key_);
}

bool SodiumChaCha20Poly1305::open(const uint8_t nonce[kNonceBytes], const uint8_t *aad,
                                  size_t aad_len, const uint8_t *in, size_t len, uint8_t *out)
{
    // Verifies the tag before decrypting; `out` is untouched on failure.
    return crypto_aead_chacha20poly1305_ietf_decrypt(out, nullptr, nullptr, in, len, aad, aad_len,
                                                     nonce, key_) == 0;
}

// ---------------- AES-256-GCM (hardware AES only) ----------------

SodiumAes256Gcm::SodiumAes256Gcm(const uint8_t key[kKeyBytes])
{
    if (sodiumAes256GcmAvailable())
        ok_ = crypto_aead_aes256gcm_beforenm(&state_, key) == 0;
    else
        sodium_memzero(&state_, sizeof(state_));
}

SodiumAes256Gcm::~SodiumAes256Gcm()
{
    sodium_memzero(&state_, sizeof(state_)); // expanded key schedule
}

void SodiumAes256Gcm::seal(const uint8_t nonce[kNonceBytes], const uint8_t *aad, size_t aad_len,
                           const uint8_t *in, size_t len, uint8_t *out)
{
    if (!ok_ || crypto_aead_aes256gcm_encrypt_afternm(out, nullptr, in, len, aad, aad_len, nullptr,
                                                      nonce, &state_) != 0)
        std::memset(out, 0, len + kTagBytes); // fail closed
}

bool SodiumAes256Gcm::open(const uint8_t nonce[kNonceBytes], const uint8_t *aad, size_t aad_len,
                           const uint8_t *in, size_t len, uint8_t *out)
{
    return ok_ && crypto_aead_aes256gcm_decrypt_afternm(out, nullptr, nullptr, in, len, aad,
                                                        aad_len, nonce, &state_) == 0;
}

} // namespace crypto
