// Bundle.h - Phase 0 onboarding bundle (design doc 03, section 5). Portable (vpnctl, clients).
//
//   cppvpn://import?b=<base64url(bundle)>
//   bundle v1 = ver u8 | node_count u8 | nodes[] | device_sk 32 | ticket 136
//   node      = id_len u8 | id | host_len u8 | host | port u16 LE | S_pub 32 | tags u32 LE
//
// The bundle contains the device private key (decision T1): it is a secret, share it only over
// a private channel. About 230 B for one node, ~310 base64url characters.
#ifndef AUTH_BUNDLE_H
#define AUTH_BUNDLE_H

#include <cstdint>
#include <string>
#include <vector>

namespace auth
{

constexpr uint8_t kBundleVersion = 1;
constexpr const char *kBundleUriPrefix = "cppvpn://import?b=";
constexpr size_t kMaxBundleNodes = 32;

struct BundleNode
{
    std::string id;   // 1..32 chars
    std::string host; // IPv4 address or DNS name, 1..253 chars
    uint16_t port = 5555;
    uint8_t pub[32] = {0}; // node S_pub (X25519)
    uint32_t tags = 0;
};

struct Bundle
{
    std::vector<BundleNode> nodes;
    uint8_t device_sk[32] = {0}; // X25519 private key of the device (Noise s)
    std::vector<uint8_t> ticket; // 136 B
    ~Bundle();
};

std::vector<uint8_t> encodeBundle(const Bundle &b);
bool decodeBundle(const uint8_t *p, size_t len, Bundle &out, std::string &error);

std::string bundleToUri(const Bundle &b);
// Accepts "cppvpn://import?b=...", a bare base64url string, or either with surrounding whitespace.
bool bundleFromText(const std::string &text, Bundle &out, std::string &error);

} // namespace auth

#endif // AUTH_BUNDLE_H
