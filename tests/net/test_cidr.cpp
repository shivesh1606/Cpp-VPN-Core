// tun_cidr parsing and the client pool derived from it (plan N5).
#include <gtest/gtest.h>

#include "net/ip/Cidr.h"

using namespace net;

namespace
{
Ipv4Cidr ok(const std::string &s)
{
    Ipv4Cidr c;
    std::string err;
    EXPECT_TRUE(parseCidr(s, c, err)) << s << ": " << err;
    return c;
}
std::string bad(const std::string &s)
{
    Ipv4Cidr c;
    std::string err;
    EXPECT_FALSE(parseCidr(s, c, err)) << s;
    return err;
}
} // namespace

TEST(Cidr, Slash24WithServerOnFirstHost)
{
    const Ipv4Cidr c = ok("10.8.0.1/24");
    EXPECT_EQ(ipv4ToString(c.addr), "10.8.0.1");
    EXPECT_EQ(c.netmask(), 0xFFFFFF00u);
    EXPECT_EQ(ipv4ToString(c.network()), "10.8.0.0");
    EXPECT_EQ(ipv4ToString(c.broadcast()), "10.8.0.255");
    EXPECT_EQ(ipv4ToString(poolStart(c)), "10.8.0.2");
    EXPECT_EQ(poolSize(c), 253u); // .2 .. .254
}

TEST(Cidr, OtherPrefixes)
{
    EXPECT_EQ(poolSize(ok("10.9.0.1/28")), 13u);   // .2 .. .14
    EXPECT_EQ(poolSize(ok("192.168.7.1/30")), 1u); // .2 only
    EXPECT_EQ(poolSize(ok("10.8.0.1/16")), 65533u);
    EXPECT_EQ(ipv4ToString(poolStart(ok("10.8.0.100/24"))), "10.8.0.101"); // pool follows server
    EXPECT_EQ(poolSize(ok("10.8.0.254/24")), 0u); // nothing left: rejected by NodeConfig
}

TEST(Cidr, Rejects)
{
    EXPECT_EQ(bad("10.8.0.1"), "expected a.b.c.d/prefix");
    EXPECT_EQ(bad("10.8.0/24"), "invalid IPv4 address '10.8.0'");
    EXPECT_EQ(bad("10.8.0.1/"), "invalid prefix ''");
    EXPECT_EQ(bad("10.8.0.1/2x"), "invalid prefix '2x'");
    EXPECT_EQ(bad("10.8.0.1/31"), "prefix /31 not supported (16..30)");
    EXPECT_EQ(bad("10.0.0.1/8"), "prefix /8 not supported (16..30)"); // pool would be 16M entries
    EXPECT_EQ(bad("10.8.0.0/24"), "address is the network or broadcast address of /24");
    EXPECT_EQ(bad("10.8.0.255/24"), "address is the network or broadcast address of /24");
}
