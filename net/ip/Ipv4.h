// Ipv4.h - Minimal IPv4 header inspection for packets read from the TUN device.
#ifndef NET_IP_IPV4_H
#define NET_IP_IPV4_H

#include <cstddef>
#include <cstdint>

namespace net
{

constexpr size_t kIpv4MinHeader = 20;

// Extracts the destination address (host byte order) of an IPv4 packet.
// Returns false if the buffer is shorter than a minimal IPv4 header or the version nibble is
// not 4 (e.g. IPv6 from the TUN device). Plan item H1: the old code read bytes 16..19
// without checking the length.
inline bool ipv4Destination(const uint8_t *pkt, size_t len, uint32_t &dst_host)
{
    if (pkt == nullptr || len < kIpv4MinHeader || (pkt[0] >> 4) != 4)
        return false;
    dst_host = (uint32_t(pkt[16]) << 24) | (uint32_t(pkt[17]) << 16) |
               (uint32_t(pkt[18]) << 8) | uint32_t(pkt[19]);
    return true;
}

} // namespace net

#endif // NET_IP_IPV4_H
