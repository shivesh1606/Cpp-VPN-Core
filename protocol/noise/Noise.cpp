#include "protocol/noise/Noise.h"

#include <sodium.h>

#include <cstring>

#include "crypto/backends/AeadLock.h" // counterNonce: identical layout to Noise section 12.3

namespace noise
{

namespace
{
constexpr size_t kBlockLen = 128; // BLAKE2b block length (Noise section 4.3: HMAC with BLOCKLEN)
}

void hash(const uint8_t *data, size_t len, uint8_t out[kHashLen])
{
    crypto_generichash(out, kHashLen, data, len, nullptr, 0);
}

void hmac(const uint8_t *key, size_t key_len, const uint8_t *data1, size_t len1,
          const uint8_t *data2, size_t len2, uint8_t out[kHashLen])
{
    // RFC 2104: keys longer than the block are hashed; then zero-padded to the block length.
    uint8_t k[kBlockLen] = {0};
    if (key_len > kBlockLen)
        hash(key, key_len, k);
    else if (key_len)
        std::memcpy(k, key, key_len);

    uint8_t pad[kBlockLen], inner[kHashLen];
    crypto_generichash_state st;

    for (size_t i = 0; i < kBlockLen; i++)
        pad[i] = k[i] ^ 0x36;
    crypto_generichash_init(&st, nullptr, 0, kHashLen);
    crypto_generichash_update(&st, pad, kBlockLen);
    if (len1)
        crypto_generichash_update(&st, data1, len1);
    if (len2)
        crypto_generichash_update(&st, data2, len2);
    crypto_generichash_final(&st, inner, kHashLen);

    for (size_t i = 0; i < kBlockLen; i++)
        pad[i] = k[i] ^ 0x5c;
    crypto_generichash_init(&st, nullptr, 0, kHashLen);
    crypto_generichash_update(&st, pad, kBlockLen);
    crypto_generichash_update(&st, inner, kHashLen);
    crypto_generichash_final(&st, out, kHashLen);

    sodium_memzero(k, sizeof(k));
    sodium_memzero(pad, sizeof(pad));
    sodium_memzero(inner, sizeof(inner));
    sodium_memzero(&st, sizeof(st));
}

void hkdf(const uint8_t ck[kHashLen], const uint8_t *ikm, size_t ikm_len, uint8_t out1[kHashLen],
          uint8_t out2[kHashLen], uint8_t *out3)
{
    uint8_t temp[kHashLen];
    const uint8_t b1 = 0x01, b2 = 0x02, b3 = 0x03;
    hmac(ck, kHashLen, ikm, ikm_len, nullptr, 0, temp);
    hmac(temp, kHashLen, &b1, 1, nullptr, 0, out1);
    hmac(temp, kHashLen, out1, kHashLen, &b2, 1, out2);
    if (out3)
        hmac(temp, kHashLen, out2, kHashLen, &b3, 1, out3);
    sodium_memzero(temp, sizeof(temp));
}

bool publicKey(const uint8_t priv[kDhLen], uint8_t pub[kDhLen])
{
    return crypto_scalarmult_base(pub, priv) == 0;
}

bool dh(const uint8_t priv[kDhLen], const uint8_t pub[kDhLen], uint8_t out[kDhLen])
{
    return crypto_scalarmult(out, priv, pub) == 0; // -1 for an all-zero (low-order) result
}

// ---------------- CipherState (section 5.1) ----------------

CipherState::~CipherState()
{
    sodium_memzero(k_, sizeof(k_));
}

void CipherState::initializeKey(const uint8_t k[kKeyLen])
{
    std::memcpy(k_, k, kKeyLen);
    n_ = 0;
    has_key_ = true;
}

size_t CipherState::encryptWithAd(const uint8_t *ad, size_t ad_len, const uint8_t *in, size_t len,
                                  uint8_t *out)
{
    if (!has_key_)
    {
        if (out != in && len)
            std::memmove(out, in, len);
        return len;
    }
    uint8_t nonce[crypto::kNonceBytes];
    crypto::counterNonce(n_++, nonce);
    crypto_aead_chacha20poly1305_ietf_encrypt(out, nullptr, in, len, ad, ad_len, nullptr, nonce, k_);
    return len + kTagLen;
}

bool CipherState::decryptWithAd(const uint8_t *ad, size_t ad_len, const uint8_t *in, size_t len,
                                uint8_t *out, size_t &out_len)
{
    if (!has_key_)
    {
        if (out != in && len)
            std::memmove(out, in, len);
        out_len = len;
        return true;
    }
    if (len < kTagLen)
        return false;
    uint8_t nonce[crypto::kNonceBytes];
    crypto::counterNonce(n_, nonce);
    if (crypto_aead_chacha20poly1305_ietf_decrypt(out, nullptr, nullptr, in, len, ad, ad_len, nonce,
                                                  k_) != 0)
        return false;
    n_++;
    out_len = len - kTagLen;
    return true;
}

// ---------------- SymmetricState (section 5.2) ----------------

SymmetricState::~SymmetricState()
{
    sodium_memzero(ck_, sizeof(ck_));
    sodium_memzero(h_, sizeof(h_));
}

void SymmetricState::initialize(const char *protocol_name)
{
    const size_t n = std::strlen(protocol_name);
    std::memset(h_, 0, kHashLen);
    if (n <= kHashLen)
        std::memcpy(h_, protocol_name, n);
    else
        hash(reinterpret_cast<const uint8_t *>(protocol_name), n, h_);
    std::memcpy(ck_, h_, kHashLen);
    cs_ = CipherState(); // no key
}

void SymmetricState::mixKey(const uint8_t *ikm, size_t len)
{
    uint8_t temp_k[kHashLen];
    hkdf(ck_, ikm, len, ck_, temp_k, nullptr); // out1 overwrites ck after temp is derived
    cs_.initializeKey(temp_k);                 // truncated to 32 bytes (HASHLEN 64)
    sodium_memzero(temp_k, sizeof(temp_k));
}

void SymmetricState::mixHash(const uint8_t *data, size_t len)
{
    crypto_generichash_state st;
    crypto_generichash_init(&st, nullptr, 0, kHashLen);
    crypto_generichash_update(&st, h_, kHashLen);
    if (len)
        crypto_generichash_update(&st, data, len);
    crypto_generichash_final(&st, h_, kHashLen);
}

size_t SymmetricState::encryptAndHash(const uint8_t *in, size_t len, uint8_t *out)
{
    const size_t n = cs_.encryptWithAd(h_, kHashLen, in, len, out);
    mixHash(out, n);
    return n;
}

bool SymmetricState::decryptAndHash(const uint8_t *in, size_t len, uint8_t *out, size_t &out_len)
{
    uint8_t h_before[kHashLen];
    std::memcpy(h_before, h_, kHashLen);
    if (!cs_.decryptWithAd(h_before, kHashLen, in, len, out, out_len))
        return false;
    mixHash(in, len); // hash of the ciphertext (in may alias out only when there is no key)
    return true;
}

void SymmetricState::split(CipherState &c1, CipherState &c2)
{
    uint8_t k1[kHashLen], k2[kHashLen];
    hkdf(ck_, nullptr, 0, k1, k2, nullptr);
    c1.initializeKey(k1);
    c2.initializeKey(k2);
    sodium_memzero(k1, sizeof(k1));
    sodium_memzero(k2, sizeof(k2));
}

// ---------------- HandshakeIK (sections 5.3, 7.5) ----------------

HandshakeIK::~HandshakeIK()
{
    sodium_memzero(s_, sizeof(s_));
    sodium_memzero(e_, sizeof(e_));
}

bool HandshakeIK::initInitiator(const uint8_t s_priv[kDhLen], const uint8_t rs_pub[kDhLen],
                                const uint8_t *prologue, size_t prologue_len)
{
    if (sodium_init() < 0)
        return false;
    std::memcpy(s_, s_priv, kDhLen);
    std::memcpy(rs_, rs_pub, kDhLen);
    if (!publicKey(s_, s_pub_))
        return false;
    ss_.initialize(kProtocolName);
    ss_.mixHash(prologue, prologue_len);
    ss_.mixHash(rs_, kDhLen); // pre-message: <- s
    return true;
}

bool HandshakeIK::initResponder(const uint8_t s_priv[kDhLen], const uint8_t *prologue,
                                size_t prologue_len)
{
    if (sodium_init() < 0)
        return false;
    std::memcpy(s_, s_priv, kDhLen);
    if (!publicKey(s_, s_pub_))
        return false;
    ss_.initialize(kProtocolName);
    ss_.mixHash(prologue, prologue_len);
    ss_.mixHash(s_pub_, kDhLen); // pre-message: <- s
    return true;
}

void HandshakeIK::setEphemeral(const uint8_t e_priv[kDhLen])
{
    std::memcpy(e_, e_priv, kDhLen);
    has_e_ = publicKey(e_, e_pub_);
}

bool HandshakeIK::ensureEphemeral()
{
    if (has_e_)
        return true;
    randombytes_buf(e_, kDhLen);
    has_e_ = publicKey(e_, e_pub_);
    return has_e_;
}

// -> e, es, s, ss
bool HandshakeIK::writeMessage1(const uint8_t *payload, size_t len, uint8_t *out, size_t &out_len)
{
    uint8_t shared[kDhLen];
    if (!ensureEphemeral())
        return false;
    std::memcpy(out, e_pub_, kDhLen);
    ss_.mixHash(e_pub_, kDhLen);
    if (!dh(e_, rs_, shared))
        return false;
    ss_.mixKey(shared, kDhLen); // es
    size_t off = kDhLen;
    off += ss_.encryptAndHash(s_pub_, kDhLen, out + off);
    if (!dh(s_, rs_, shared))
        return false;
    ss_.mixKey(shared, kDhLen); // ss
    off += ss_.encryptAndHash(payload, len, out + off);
    sodium_memzero(shared, sizeof(shared));
    out_len = off;
    return true;
}

bool HandshakeIK::readMessage1(const uint8_t *msg, size_t len, uint8_t *payload, size_t &payload_len)
{
    if (len < kMsg1Overhead)
        return false;
    uint8_t shared[kDhLen];
    std::memcpy(re_, msg, kDhLen);
    ss_.mixHash(re_, kDhLen);
    if (!dh(s_, re_, shared))
        return false;
    ss_.mixKey(shared, kDhLen); // es
    size_t n = 0;
    if (!ss_.decryptAndHash(msg + kDhLen, kDhLen + kTagLen, rs_, n) || n != kDhLen)
        return false;
    if (!dh(s_, rs_, shared))
        return false;
    ss_.mixKey(shared, kDhLen); // ss
    const size_t off = kDhLen + kDhLen + kTagLen;
    const bool ok = ss_.decryptAndHash(msg + off, len - off, payload, payload_len);
    sodium_memzero(shared, sizeof(shared));
    return ok;
}

// <- e, ee, se
bool HandshakeIK::writeMessage2(const uint8_t *payload, size_t len, uint8_t *out, size_t &out_len)
{
    uint8_t shared[kDhLen];
    if (!ensureEphemeral())
        return false;
    std::memcpy(out, e_pub_, kDhLen);
    ss_.mixHash(e_pub_, kDhLen);
    if (!dh(e_, re_, shared))
        return false;
    ss_.mixKey(shared, kDhLen); // ee
    if (!dh(e_, rs_, shared))
        return false;
    ss_.mixKey(shared, kDhLen); // se (responder side: DH(e, rs))
    out_len = kDhLen + ss_.encryptAndHash(payload, len, out + kDhLen);
    sodium_memzero(shared, sizeof(shared));
    return true;
}

bool HandshakeIK::readMessage2(const uint8_t *msg, size_t len, uint8_t *payload, size_t &payload_len)
{
    if (len < kMsg2Overhead)
        return false;
    uint8_t shared[kDhLen];
    std::memcpy(re_, msg, kDhLen);
    ss_.mixHash(re_, kDhLen);
    if (!dh(e_, re_, shared))
        return false;
    ss_.mixKey(shared, kDhLen); // ee
    if (!dh(s_, re_, shared))
        return false;
    ss_.mixKey(shared, kDhLen); // se (initiator side: DH(s, re))
    const bool ok = ss_.decryptAndHash(msg + kDhLen, len - kDhLen, payload, payload_len);
    sodium_memzero(shared, sizeof(shared));
    return ok;
}

} // namespace noise
