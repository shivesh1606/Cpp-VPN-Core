// Ticket.h - access ticket v1 (design doc 03, section 2). Portable: shared by the node
// (verification), vpnctl (issuing) and clients (opaque bytes in HS_INIT).
//
//  0     1        2      3      4         20          52     56    60    64          72       136
//  | ver | key_id | tier | rsvd | user_id | device_pk | tags | nbf | exp | ticket_id | sig     |
//  | u8  | u8     | u8   | u8=0 | 16 B    | 32 B      | u32  | u32 | u32 | u64       | 64 B    |
//  Integers little-endian. sig = Ed25519(issuer_sk[key_id], "cppvpn-ticket-v1" || bytes[0:72]).
//
// Verification order (section 2.1), each failure with its own reason / drop counter:
//   FORMAT, UNKNOWN_KEY, SIG, EXPIRED, SCOPE, DEVICE, REVOKED.
#ifndef AUTH_TICKET_H
#define AUTH_TICKET_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>

namespace auth
{

class RevocationList;

constexpr size_t kTicketLen = 136;
constexpr size_t kTicketBodyLen = 72;
constexpr size_t kUserIdLen = 16;
constexpr uint8_t kTicketVersion = 1;
constexpr uint32_t kClockSkewS = 60; // nodes accept nbf - 60 <= now < exp + 60
constexpr const char *kTicketContext = "cppvpn-ticket-v1";

using PublicKey = std::array<uint8_t, 32>; // Ed25519
using IssuerKeys = std::map<uint8_t, PublicKey>; // key_id -> issuer public key (rotation, section 4)

struct Ticket
{
    uint8_t ver = kTicketVersion;
    uint8_t key_id = 0;
    uint8_t tier = 0; // reserved for monetization; ignored by nodes for now
    uint8_t user_id[kUserIdLen] = {0};
    uint8_t device_pk[32] = {0}; // must equal the Noise initiator static key s_c
    uint32_t tags = 0;           // bit i: valid on nodes carrying tag i (tags.conf)
    uint32_t nbf = 0, exp = 0;   // Unix seconds
    uint64_t ticket_id = 0;      // revocation handle
    uint8_t sig[64] = {0};
};

// Reasons in verification order. The numeric values index the node's drop counters.
enum class Verdict : uint8_t
{
    kOk = 0,
    kFormat,
    kUnknownKey,
    kSig,
    kExpired,
    kScope,
    kDevice,
    kRevoked,
    kCount
};
const char *verdictName(Verdict v); // "ok", "format", "unknown_key", ...

void encodeBody(const Ticket &t, uint8_t out[kTicketBodyLen]);
void encode(const Ticket &t, uint8_t out[kTicketLen]);
// Parses the layout only (no signature check). False unless len == 136, ver == 1, rsvd == 0.
bool decode(const uint8_t *p, size_t len, Ticket &out);

// Signs body with an Ed25519 secret key (64 bytes, libsodium layout) and fills t.sig.
bool sign(Ticket &t, const uint8_t issuer_sk[64]);

// Full check of section 2.1. `revoked` may be null (no list yet). `out` (optional) receives the
// decoded ticket when the format is valid.
Verdict verify(const uint8_t *bytes, size_t len, const uint8_t s_c[32], uint64_t now_unix,
               const IssuerKeys &issuers, uint32_t node_mask, const RevocationList *revoked,
               Ticket *out = nullptr);

} // namespace auth

#endif // AUTH_TICKET_H
