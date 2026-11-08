// OpenSslAead.h - OpenSSL EVP AEAD primitives (optional, CMake -DWITH_OPENSSL=ON).
//
// Second implementation of the same wire algorithms, for benchmark comparisons and for the
// cross-implementation test (design 01, constraint C5). Also provides AES-256-GCM on ARM,
// where libsodium 1.0.18 has none.
//
//   OpenSslChaCha20Poly1305  cipher_id 1  EVP_chacha20_poly1305()
//   OpenSslAes256Gcm         cipher_id 2  EVP_aes_256_gcm()
//
// Per-key setup (C3): two EVP_CIPHER_CTX (encrypt, decrypt) are created and keyed in the
// constructor. Per packet only the IV is set, so the key schedule is not recomputed.
#ifndef CRYPTO_BACKENDS_OPENSSLAEAD_H
#define CRYPTO_BACKENDS_OPENSSLAEAD_H

#include "crypto/backends/AeadLock.h"

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;

namespace crypto
{

// "OpenSSL 3.0.2 15 Mar 2022" etc.
const char *openSslVersion();

class OpenSslAead
{
public:
    OpenSslAead(const EVP_CIPHER *cipher, const uint8_t key[kKeyBytes]);
    ~OpenSslAead();
    OpenSslAead(const OpenSslAead &) = delete;
    OpenSslAead &operator=(const OpenSslAead &) = delete;

    void seal(const uint8_t nonce[kNonceBytes], const uint8_t *aad, size_t aad_len,
              const uint8_t *in, size_t len, uint8_t *out);
    bool open(const uint8_t nonce[kNonceBytes], const uint8_t *aad, size_t aad_len,
              const uint8_t *in, size_t len, uint8_t *out);

private:
    EVP_CIPHER_CTX *enc_ = nullptr;
    EVP_CIPHER_CTX *dec_ = nullptr;
    bool ok_ = false;
};

class OpenSslChaCha20Poly1305 : public OpenSslAead
{
public:
    static constexpr uint8_t kId = kCipherChaCha20Poly1305;
    static constexpr const char *kAlgorithm = "chacha20poly1305";
    static constexpr const char *kImpl = "openssl";
    explicit OpenSslChaCha20Poly1305(const uint8_t key[kKeyBytes]);
};

class OpenSslAes256Gcm : public OpenSslAead
{
public:
    static constexpr uint8_t kId = kCipherAes256Gcm;
    static constexpr const char *kAlgorithm = "aes256gcm";
    static constexpr const char *kImpl = "openssl";
    explicit OpenSslAes256Gcm(const uint8_t key[kKeyBytes]);
};

} // namespace crypto

#endif // CRYPTO_BACKENDS_OPENSSLAEAD_H
