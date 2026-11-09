// IssuerKey.h - passphrase-encrypted issuer signing key (design doc 03, section 4, Phase 0).
//
// File (149 B, mode 0600):
//   magic "CPPVPNIK" | ver u8=1 | key_id u8 | alg u8 (2 = Argon2id v1.3) | rsvd u8
//   | opslimit u64 LE | memlimit u64 LE | salt 16 | nonce 24 | secretbox(key_id || ed25519_sk 64) 81
// key = crypto_pwhash(passphrase, salt, opslimit, memlimit, Argon2id); the key_id is inside the
// box as well, so a header edit cannot relabel the key.
#ifndef AUTH_ISSUERKEY_H
#define AUTH_ISSUERKEY_H

#include <cstdint>
#include <string>

namespace auth
{

enum class KdfStrength
{
    kInteractive, // ~0.1 s, 64 MiB (tests)
    kModerate,    // ~0.7 s, 256 MiB (default)
    kSensitive,   // ~3.5 s, 1 GiB
};

struct IssuerKey
{
    uint8_t key_id = 1;
    uint8_t sk[64] = {0}; // Ed25519 secret key (libsodium layout: seed || pk)
    uint8_t pk[32] = {0};
    ~IssuerKey();
};

// Generates a key pair. False if libsodium fails.
bool generateIssuerKey(uint8_t key_id, IssuerKey &out);
// Writes `key` encrypted under `passphrase`; refuses to overwrite an existing file.
bool saveIssuerKey(const std::string &path, const IssuerKey &key, const std::string &passphrase,
                   KdfStrength strength, std::string &error);
// Reads and decrypts. "wrong passphrase or damaged file" on authentication failure.
bool loadIssuerKey(const std::string &path, const std::string &passphrase, IssuerKey &out, std::string &error);

} // namespace auth

#endif // AUTH_ISSUERKEY_H
