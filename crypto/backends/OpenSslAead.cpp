#include "crypto/backends/OpenSslAead.h"

#include <climits>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "crypto/backends/VectorState.h"

namespace crypto
{

const char *openSslVersion()
{
    return OpenSSL_version(OPENSSL_VERSION);
}

OpenSslAead::OpenSslAead(const EVP_CIPHER *cipher, const uint8_t key[kKeyBytes])
{
    enc_ = EVP_CIPHER_CTX_new();
    dec_ = EVP_CIPHER_CTX_new();
    // Both algorithms default to a 12-byte IV, which is what counterNonce() produces.
    ok_ = cipher && enc_ && dec_ &&
          EVP_EncryptInit_ex(enc_, cipher, nullptr, key, nullptr) == 1 &&
          EVP_DecryptInit_ex(dec_, cipher, nullptr, key, nullptr) == 1 &&
          EVP_CIPHER_CTX_iv_length(enc_) == static_cast<int>(kNonceBytes);
}

OpenSslAead::~OpenSslAead()
{
    EVP_CIPHER_CTX_free(enc_); // also cleanses the key schedule
    EVP_CIPHER_CTX_free(dec_);
}

void OpenSslAead::seal(const uint8_t nonce[kNonceBytes], const uint8_t *aad, size_t aad_len,
                       const uint8_t *in, size_t len, uint8_t *out)
{
    int n = 0;
    const bool ok =
        ok_ && len <= INT_MAX && aad_len <= INT_MAX &&
        EVP_EncryptInit_ex(enc_, nullptr, nullptr, nullptr, nonce) == 1 && // new IV, same key
        (aad_len == 0 || EVP_EncryptUpdate(enc_, nullptr, &n, aad, static_cast<int>(aad_len)) == 1) &&
        (len == 0 || EVP_EncryptUpdate(enc_, out, &n, in, static_cast<int>(len)) == 1) &&
        EVP_EncryptFinal_ex(enc_, out + len, &n) == 1 && // stream modes: writes 0 bytes
        EVP_CIPHER_CTX_ctrl(enc_, EVP_CTRL_AEAD_GET_TAG, kTagBytes, out + len) == 1;
    if (!ok)
        std::memset(out, 0, len + kTagBytes); // fail closed
    clearUpperVectorState(); // don't slow down SSE code that runs next (VectorState.h)
}

bool OpenSslAead::open(const uint8_t nonce[kNonceBytes], const uint8_t *aad, size_t aad_len,
                       const uint8_t *in, size_t len, uint8_t *out)
{
    if (!ok_ || len < kTagBytes || len > INT_MAX || aad_len > INT_MAX)
        return false;
    const size_t ct_len = len - kTagBytes;
    int n = 0;
    const bool ok =
        EVP_DecryptInit_ex(dec_, nullptr, nullptr, nullptr, nonce) == 1 &&
        (aad_len == 0 || EVP_DecryptUpdate(dec_, nullptr, &n, aad, static_cast<int>(aad_len)) == 1) &&
        (ct_len == 0 || EVP_DecryptUpdate(dec_, out, &n, in, static_cast<int>(ct_len)) == 1) &&
        EVP_CIPHER_CTX_ctrl(dec_, EVP_CTRL_AEAD_SET_TAG, kTagBytes,
                            const_cast<uint8_t *>(in + ct_len)) == 1 &&
        EVP_DecryptFinal_ex(dec_, out + ct_len, &n) > 0; // tag check
    if (!ok && ct_len)
        std::memset(out, 0, ct_len); // OpenSSL decrypts before verifying: wipe unverified data
    clearUpperVectorState();
    return ok;
}

OpenSslChaCha20Poly1305::OpenSslChaCha20Poly1305(const uint8_t key[kKeyBytes])
    : OpenSslAead(EVP_chacha20_poly1305(), key) {}

OpenSslAes256Gcm::OpenSslAes256Gcm(const uint8_t key[kKeyBytes])
    : OpenSslAead(EVP_aes_256_gcm(), key) {}

} // namespace crypto
