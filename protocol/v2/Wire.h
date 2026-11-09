// Wire.h - protocol v2 packet layouts (design doc 02, section 3). Portable (server + clients).
//
// Byte order: indexes, counters and lengths are little-endian (as WireGuard); tun_ip is in network
// order (it is an IPv4 address); TAI64N is big-endian by definition, so timestamps compare with memcmp.
//
//   HS_INIT  ver type sender_idx | e 32 | enc(s) 48 | enc(payload1) n+16 | mac1 16 | mac2 16
//   HS_RESP  ver type sender_idx receiver_idx | e 32 | enc(payload2) 7+16 | mac1 16 | mac2 16 = 97 B
//   transport (ACK/DATA/BYE/KEEPALIVE): ver type receiver_idx counter_u64 (14 B, the AAD) | ct | tag 16
//
//   payload1 = ts TAI64N 12 | offer_n u8 | offer[offer_n] | ticket_len u16 | ticket
//   payload2 = tun_ip u32 | cipher_id u8 | keepalive_s u16
//   ACK payload = handshake_id 8 (counter 0)
#ifndef PROTOCOL_V2_WIRE_H
#define PROTOCOL_V2_WIRE_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "protocol/noise/Noise.h"

namespace v2
{

constexpr uint8_t kVersion = 0x20; // never a v1 type byte (1..6), so the first byte demultiplexes
constexpr const char *kPrologue = "cppvpn-v2";
constexpr size_t kPrologueLen = 9;

enum Type : uint8_t
{
    kHsInit = 1,
    kHsResp = 2,
    kAck = 3,
    kData = 4,
    kBye = 5,
    kKeepalive = 6,
    kCookieReply = 7, // reserved (design 02 D2)
};

constexpr size_t kMacLen = 16;
constexpr size_t kMacsLen = 2 * kMacLen;
constexpr size_t kInitHeaderLen = 6;  // ver, type, sender_idx
constexpr size_t kRespHeaderLen = 10; // ver, type, sender_idx, receiver_idx
constexpr size_t kTransportHeaderLen = 14;
constexpr size_t kTagLen = 16;
constexpr size_t kTai64nLen = 12;
constexpr size_t kHandshakeIdLen = 8;
constexpr size_t kPayload2Len = 7;
constexpr size_t kMaxOffer = 8;
constexpr size_t kMaxTicket = 512;

constexpr size_t kPayload1MinLen = kTai64nLen + 1 + 2;
constexpr size_t kInitMinLen = kInitHeaderLen + noise::HandshakeIK::kMsg1Overhead + kPayload1MinLen + kMacsLen;
constexpr size_t kInitMaxLen = kInitMinLen + kMaxOffer + kMaxTicket;
constexpr size_t kRespLen = kRespHeaderLen + noise::HandshakeIK::kMsg2Overhead + kPayload2Len + kMacsLen; // 97
constexpr size_t kAckLen = kTransportHeaderLen + kHandshakeIdLen + kTagLen;                            // 38
constexpr size_t kTransportMinLen = kTransportHeaderLen + kTagLen;                                      // 30

// ---- little-endian helpers ----
inline void putU16(uint8_t *p, uint16_t v) { p[0] = uint8_t(v); p[1] = uint8_t(v >> 8); }
inline void putU32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = uint8_t(v >> (8 * i)); }
inline void putU64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = uint8_t(v >> (8 * i)); }
inline uint16_t getU16(const uint8_t *p) { return uint16_t(p[0] | (p[1] << 8)); }
inline uint32_t getU32(const uint8_t *p)
{
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
inline uint64_t getU64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = v << 8 | p[i];
    return v;
}

// ---- transport header ----
struct TransportHeader
{
    uint8_t type = 0;
    uint32_t receiver_idx = 0;
    uint64_t counter = 0;
};
inline void writeTransportHeader(uint8_t *p, uint8_t type, uint32_t receiver_idx, uint64_t counter)
{
    p[0] = kVersion;
    p[1] = type;
    putU32(p + 2, receiver_idx);
    putU64(p + 6, counter);
}
inline bool readTransportHeader(const uint8_t *p, size_t len, TransportHeader &h)
{
    if (len < kTransportMinLen || p[0] != kVersion || p[1] < kAck || p[1] > kKeepalive)
        return false;
    h.type = p[1];
    h.receiver_idx = getU32(p + 2);
    h.counter = getU64(p + 6);
    return true;
}

// ---- TAI64N (https://cr.yp.to/libtai/tai64.html) ----
// label = 2^62 + seconds since the Unix epoch, then nanoseconds; both big-endian.
void tai64n(uint64_t unix_seconds, uint32_t nanoseconds, uint8_t out[kTai64nLen]);
void tai64nNow(uint8_t out[kTai64nLen]);
inline int compareTai64n(const uint8_t a[kTai64nLen], const uint8_t b[kTai64nLen])
{
    return std::memcmp(a, b, kTai64nLen);
}

// ---- mac1 (section 3.3) ----
// mac1_key = BLAKE2b-256("mac1----" || static_pub); mac1 = BLAKE2b-128(mac1_key, msg[0:len-32]).
void mac1Key(const uint8_t static_pub[32], uint8_t key[32]);
void computeMac1(const uint8_t key[32], const uint8_t *msg, size_t len_before_mac1, uint8_t out[kMacLen]);
// Checks mac1 of a whole HS_INIT/HS_RESP packet (mac1 sits at len-32).
bool verifyMac1(const uint8_t key[32], const uint8_t *pkt, size_t len);

// ---- handshake payloads ----
struct Payload1
{
    uint8_t ts[kTai64nLen] = {0};
    std::vector<uint8_t> offer;  // cipher_id values, client preference order
    std::vector<uint8_t> ticket; // opaque here (design 03), empty until M5
};
std::vector<uint8_t> encodePayload1(const Payload1 &p);
bool decodePayload1(const uint8_t *p, size_t len, Payload1 &out);

struct Payload2
{
    uint32_t tun_ip = 0; // host order in this struct, network order on the wire
    uint8_t cipher_id = 0;
    uint16_t keepalive_s = 0;
};
void encodePayload2(const Payload2 &p, uint8_t out[kPayload2Len]);
bool decodePayload2(const uint8_t *p, size_t len, Payload2 &out);

// Handshake ID (section 8): the first 8 bytes of the final handshake hash, as 16 hex chars.
std::string handshakeIdHex(const uint8_t id[kHandshakeIdLen]);

} // namespace v2

#endif // PROTOCOL_V2_WIRE_H
