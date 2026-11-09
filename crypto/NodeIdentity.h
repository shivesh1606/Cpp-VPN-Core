// NodeIdentity.h - the node's static X25519 key pair (plan decision N1; design 02 section 2).
//
// File format: one line, the 32-byte private key as base64url without padding (43 chars).
// The public key S_pub is derived on load (crypto_scalarmult_base) and is what clients pin
// (Noise IK "s" of the responder, distributed in bundles, design 03).
//
//   vpn_server --gen-key /etc/cppvpn/node.key    -> writes mode 0600, prints S_pub
//   vpn_server --pubkey  /etc/cppvpn/node.key    -> prints S_pub
//
// Loading refuses files that are not regular files or that group/others can access
// (same rule as OpenSSH for private keys).
#ifndef CRYPTO_NODEIDENTITY_H
#define CRYPTO_NODEIDENTITY_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace crypto
{

constexpr size_t kX25519Bytes = 32;

class NodeIdentity
{
public:
    NodeIdentity() = default;
    ~NodeIdentity();
    NodeIdentity(const NodeIdentity &) = delete;
    NodeIdentity &operator=(const NodeIdentity &) = delete;

    bool loaded() const { return loaded_; }
    const uint8_t *publicKey() const { return pk_; }
    const uint8_t *privateKey() const { return sk_; } // used by the Noise responder (M4)
    std::string publicKeyBase64Url() const;

    // Sets the key pair from a private key; derives the public key. False if libsodium fails.
    bool setPrivateKey(const uint8_t sk[kX25519Bytes]);

private:
    uint8_t sk_[kX25519Bytes] = {0};
    uint8_t pk_[kX25519Bytes] = {0};
    bool loaded_ = false;
};

// base64url, no padding (RFC 4648 section 5).
std::string toBase64Url(const uint8_t *data, size_t len);
// Decodes base64url without padding; true only if it decodes to exactly `len` bytes.
bool fromBase64Url(const std::string &text, uint8_t *out, size_t len);

// Generates a key pair and writes the private key to `path` with mode 0600 (via a temporary
// file and rename). Refuses to replace an existing file unless `overwrite`.
bool generateNodeKey(const std::string &path, bool overwrite, NodeIdentity &out, std::string &error);

// Loads a private key file written by generateNodeKey.
bool loadNodeKey(const std::string &path, NodeIdentity &out, std::string &error);

} // namespace crypto

#endif // CRYPTO_NODEIDENTITY_H
