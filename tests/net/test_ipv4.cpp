// net::ipv4Destination: plan item H1 (TUN read path must not read past short packets).
#include <gtest/gtest.h>

#include <vector>

#include "net/ip/Ipv4.h"

namespace
{

std::vector<uint8_t> ipv4Packet(size_t len, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    std::vector<uint8_t> p(len, 0);
    p[0] = 0x45; // version 4, IHL 5
    p[16] = a;
    p[17] = b;
    p[18] = c;
    p[19] = d;
    return p;
}

} // namespace

TEST(Ipv4Destination, ParsesHostOrderDestination)
{
    auto p = ipv4Packet(84, 10, 8, 0, 2);
    uint32_t dst = 0;
    ASSERT_TRUE(net::ipv4Destination(p.data(), p.size(), dst));
    EXPECT_EQ(dst, 0x0A080002u);
}

TEST(Ipv4Destination, AcceptsExactlyMinimalHeader)
{
    auto p = ipv4Packet(20, 192, 168, 1, 1);
    uint32_t dst = 0;
    EXPECT_TRUE(net::ipv4Destination(p.data(), p.size(), dst));
    EXPECT_EQ(dst, 0xC0A80101u);
}

TEST(Ipv4Destination, RejectsShortPackets)
{
    auto p = ipv4Packet(20, 10, 8, 0, 2);
    uint32_t dst = 0xdeadbeef;
    for (size_t len = 0; len < net::kIpv4MinHeader; len++)
    {
        EXPECT_FALSE(net::ipv4Destination(p.data(), len, dst)) << "len " << len;
        EXPECT_EQ(dst, 0xdeadbeefu) << "output must be untouched on failure";
    }
}

TEST(Ipv4Destination, RejectsNonIpv4Versions)
{
    auto p = ipv4Packet(40, 10, 8, 0, 2);
    uint32_t dst = 0;
    p[0] = 0x60; // IPv6
    EXPECT_FALSE(net::ipv4Destination(p.data(), p.size(), dst));
    p[0] = 0x00;
    EXPECT_FALSE(net::ipv4Destination(p.data(), p.size(), dst));
}

TEST(Ipv4Destination, RejectsNull)
{
    uint32_t dst = 0;
    EXPECT_FALSE(net::ipv4Destination(nullptr, 100, dst));
}
