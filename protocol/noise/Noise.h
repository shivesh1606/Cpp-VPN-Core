// Noise.h - Noise_IK_25519_ChaChaPoly_BLAKE2b on libsodium (design doc 02, decision D1).
//
// Follows The Noise Protocol Framework, revision 34 (https://noiseprotocol.org/noise.html):
//   section 4   crypto functions: DH = X25519, HASH = BLAKE2b-512, HMAC per RFC 2104 (block 128),
//               HKDF per section 4.3 (Noise's own two/three-output construction)
//   section 5   CipherState, SymmetricState, HandshakeState processing rules
//   section 7.5 the IK pattern:   <- s  ...  -> e, es, s, ss   <- e, ee, se
//   section 12.3 ChaChaPoly nonce = 32 zero bits || 64-bit little-endian n
// Only the IK pattern is implemented. Correctness is gated by the published test vectors
// (tests/protocol/test_noise_vectors.cpp). Portable: no OS headers (also built for Windows).
#ifndef PROTOCOL_NOISE_NOISE_H
#define PROTOCOL_NOISE_NOISE_H

#include <cstddef>
#include <cstdint>

namespace noise
{

constexpr size_t kHashLen = 64; // BLAKE2b-512
constexpr size_t kDhLen = 32;   // X25519
constexpr size_t kKeyLen = 32;
constexpr size_t kTagLen = 16;
constexpr const char *kProtocolName = "Noise_IK_25519_ChaChaPoly_BLAKE2b";

// HASH(data) = BLAKE2b-512.
void hash(const uint8_t *data, size_t len, uint8_t out[kHashLen]);
// HMAC-HASH(key, data1 || data2) per RFC 2104 with BLAKE2b (block length 128).
void hmac(const uint8_t *key, size_t key_len, const uint8_t *data1, size_t len1,
          const uint8_t *data2, size_t len2, uint8_t out[kHashLen]);
// HKDF(chaining_key, ikm) per Noise section 4.3; out3 may be null (two outputs).
void hkdf(const uint8_t ck[kHashLen], const uint8_t *ikm, size_t ikm_len, uint8_t out1[kHashLen],
          uint8_t out2[kHashLen], uint8_t *out3);

// X25519 key pair helpers. dh() returns false for an all-zero result (low-order point).
bool publicKey(const uint8_t priv[kDhLen], uint8_t pub[kDhLen]);
bool dh(const uint8_t priv[kDhLen], const uint8_t pub[kDhLen], uint8_t out[kDhLen]);

class CipherState
{
public:
    ~CipherState();
    void initializeKey(const uint8_t k[kKeyLen]);
    bool hasKey() const { return has_key_; }
    const uint8_t *key() const { return k_; }
    uint64_t nonce() const { return n_; }

    // Writes ciphertext || tag (or the plaintext if no key yet); returns bytes written.
    // `out` may equal `in`.
    size_t encryptWithAd(const uint8_t *ad, size_t ad_len, const uint8_t *in, size_t len, uint8_t *out);
    // Reverses encryptWithAd. False on authentication failure (n is not advanced then).
    bool decryptWithAd(const uint8_t *ad, size_t ad_len, const uint8_t *in, size_t len,
                       uint8_t *out, size_t &out_len);

private:
    uint8_t k_[kKeyLen] = {0};
    uint64_t n_ = 0;
    bool has_key_ = false;
};

class SymmetricState
{
public:
    ~SymmetricState();
    void initialize(const char *protocol_name);
    void mixKey(const uint8_t *ikm, size_t len);
    void mixHash(const uint8_t *data, size_t len);
    size_t encryptAndHash(const uint8_t *in, size_t len, uint8_t *out);
    bool decryptAndHash(const uint8_t *in, size_t len, uint8_t *out, size_t &out_len);
    void split(CipherState &c1, CipherState &c2);
    const uint8_t *handshakeHash() const { return h_; }

private:
    uint8_t ck_[kHashLen] = {0};
    uint8_t h_[kHashLen] = {0};
    CipherState cs_;
};

// IK handshake. Message sizes: msg1 = 32 + 48 + payload1 + 16, msg2 = 32 + payload2 + 16.
class HandshakeIK
{
public:
    static constexpr size_t kMsg1Overhead = kDhLen + kDhLen + kTagLen + kTagLen; // 96
    static constexpr size_t kMsg2Overhead = kDhLen + kTagLen;                    // 48

    ~HandshakeIK();

    // Initiator knows the responder's static public key `rs` up front.
    bool initInitiator(const uint8_t s_priv[kDhLen], const uint8_t rs_pub[kDhLen],
                       const uint8_t *prologue, size_t prologue_len);
    bool initResponder(const uint8_t s_priv[kDhLen], const uint8_t *prologue, size_t prologue_len);
    // Test vectors use fixed ephemerals; otherwise a random one is generated when needed.
    void setEphemeral(const uint8_t e_priv[kDhLen]);

    bool writeMessage1(const uint8_t *payload, size_t len, uint8_t *out, size_t &out_len); // initiator
    bool readMessage1(const uint8_t *msg, size_t len, uint8_t *payload, size_t &payload_len); // responder
    bool writeMessage2(const uint8_t *payload, size_t len, uint8_t *out, size_t &out_len); // responder
    bool readMessage2(const uint8_t *msg, size_t len, uint8_t *payload, size_t &payload_len); // initiator

    // After message 2: c1 = initiator -> responder, c2 = responder -> initiator.
    void split(CipherState &c1, CipherState &c2) { ss_.split(c1, c2); }
    const uint8_t *handshakeHash() const { return ss_.handshakeHash(); }
    const uint8_t *remoteStatic() const { return rs_; } // the initiator's s, on the responder

private:
    bool ensureEphemeral();

    SymmetricState ss_;
    uint8_t s_[kDhLen] = {0}, s_pub_[kDhLen] = {0};
    uint8_t e_[kDhLen] = {0}, e_pub_[kDhLen] = {0};
    uint8_t rs_[kDhLen] = {0}, re_[kDhLen] = {0};
    bool has_e_ = false;
};

} // namespace noise

#endif // PROTOCOL_NOISE_NOISE_H
