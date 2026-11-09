#include "protocol/v2/Wire.h"

#include <sodium.h>

#include <chrono>
#include <string>

namespace v2
{

void tai64n(uint64_t unix_seconds, uint32_t nanoseconds, uint8_t out[kTai64nLen])
{
    const uint64_t label = (uint64_t(1) << 62) + unix_seconds;
    for (int i = 0; i < 8; i++)
        out[i] = uint8_t(label >> (56 - 8 * i));
    for (int i = 0; i < 4; i++)
        out[8 + i] = uint8_t(nanoseconds >> (24 - 8 * i));
}

void tai64nNow(uint8_t out[kTai64nLen])
{
    using namespace std::chrono;
    const auto ns = duration_cast<nanoseconds>(system_clock::now().time_since_epoch()).count();
    tai64n(uint64_t(ns / 1000000000), uint32_t(ns % 1000000000), out);
}

void mac1Key(const uint8_t static_pub[32], uint8_t key[32])
{
    uint8_t in[8 + 32];
    std::memcpy(in, "mac1----", 8);
    std::memcpy(in + 8, static_pub, 32);
    crypto_generichash(key, 32, in, sizeof(in), nullptr, 0);
}

void computeMac1(const uint8_t key[32], const uint8_t *msg, size_t len_before_mac1, uint8_t out[kMacLen])
{
    crypto_generichash(out, kMacLen, msg, len_before_mac1, key, 32);
}

bool verifyMac1(const uint8_t key[32], const uint8_t *pkt, size_t len)
{
    if (len < kMacsLen)
        return false;
    uint8_t mac[kMacLen];
    computeMac1(key, pkt, len - kMacsLen, mac);
    return sodium_memcmp(mac, pkt + len - kMacsLen, kMacLen) == 0; // constant time
}

std::vector<uint8_t> encodePayload1(const Payload1 &p)
{
    std::vector<uint8_t> out(kTai64nLen);
    std::memcpy(out.data(), p.ts, kTai64nLen);
    out.push_back(uint8_t(p.offer.size()));
    out.insert(out.end(), p.offer.begin(), p.offer.end());
    out.push_back(uint8_t(p.ticket.size()));
    out.push_back(uint8_t(p.ticket.size() >> 8));
    out.insert(out.end(), p.ticket.begin(), p.ticket.end());
    return out;
}

bool decodePayload1(const uint8_t *p, size_t len, Payload1 &out)
{
    if (len < kPayload1MinLen)
        return false;
    std::memcpy(out.ts, p, kTai64nLen);
    size_t off = kTai64nLen;
    const size_t n = p[off++];
    if (n == 0 || n > kMaxOffer || off + n + 2 > len)
        return false;
    out.offer.assign(p + off, p + off + n);
    off += n;
    const size_t t = getU16(p + off);
    off += 2;
    if (t > kMaxTicket || off + t != len) // exact length: no trailing bytes
        return false;
    out.ticket.assign(p + off, p + off + t);
    return true;
}

void encodePayload2(const Payload2 &p, uint8_t out[kPayload2Len])
{
    out[0] = uint8_t(p.tun_ip >> 24); // network order
    out[1] = uint8_t(p.tun_ip >> 16);
    out[2] = uint8_t(p.tun_ip >> 8);
    out[3] = uint8_t(p.tun_ip);
    out[4] = p.cipher_id;
    putU16(out + 5, p.keepalive_s);
}

bool decodePayload2(const uint8_t *p, size_t len, Payload2 &out)
{
    if (len != kPayload2Len)
        return false;
    out.tun_ip = uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3];
    out.cipher_id = p[4];
    out.keepalive_s = getU16(p + 5);
    return true;
}

std::string handshakeIdHex(const uint8_t id[kHandshakeIdLen])
{
    static const char *d = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < kHandshakeIdLen; i++)
        s += {d[id[i] >> 4], d[id[i] & 15]};
    return s;
}

} // namespace v2
