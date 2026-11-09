// tags.conf (design 03 section 3) and the onboarding bundle (section 5).
#include <gtest/gtest.h>

#include <cstring>

#include "auth/Bundle.h"
#include "auth/TagRegistry.h"
#include "auth/Ticket.h"

using namespace auth;

TEST(TagRegistry, ParsesTheDesignExample)
{
    TagRegistry r;
    std::string err;
    ASSERT_TRUE(r.parse("# bit = name\n0 = friends\n1 = free\n2 = premium\n8 = region-in   # India\n9 = region-us\n", err)) << err;
    uint32_t m = 0;
    ASSERT_TRUE(r.mask({"friends", "region-in"}, m, err)) << err;
    EXPECT_EQ(m, (1u << 0) | (1u << 8));
    EXPECT_EQ(r.names(m), "friends, region-in");
    EXPECT_EQ(r.names(1u << 31), "bit31");
    EXPECT_FALSE(r.mask({"friends", "gold"}, m, err));
    EXPECT_EQ(err, "unknown tag 'gold' (not in tags.conf)");
    EXPECT_FALSE(r.mask({}, m, err));
}

TEST(TagRegistry, Errors)
{
    TagRegistry r;
    std::string err;
    EXPECT_FALSE(r.parse("0 = a\n0 = b\n", err));
    EXPECT_EQ(err, "line 2: bit 0 already used by 'a'");
    EXPECT_FALSE(r.parse("0 = a\n1 = a\n", err));
    EXPECT_EQ(err, "line 2: tag 'a' already defined (bit 0)");
    EXPECT_FALSE(r.parse("32 = a\n", err));
    EXPECT_FALSE(r.parse("x = a\n", err));
    EXPECT_FALSE(r.parse("1 a\n", err));
    EXPECT_FALSE(r.parse("1 = bad name\n", err));
}

namespace
{
Bundle sampleBundle(int nodes = 1)
{
    Bundle b;
    for (int i = 0; i < nodes; i++)
    {
        BundleNode n;
        n.id = "in-" + std::to_string(i + 1);
        n.host = i ? "vpn" + std::to_string(i) + ".example.org" : "35.200.10.20";
        n.port = uint16_t(5555 + i);
        for (int k = 0; k < 32; k++)
            n.pub[k] = uint8_t(k + i);
        n.tags = 0x101;
        b.nodes.push_back(n);
    }
    for (int k = 0; k < 32; k++)
        b.device_sk[k] = uint8_t(200 + k);
    b.ticket.assign(kTicketLen, 0x5a);
    return b;
}
} // namespace

TEST(Bundle, UriRoundTripAndSize)
{
    const Bundle b = sampleBundle();
    const std::string uri = bundleToUri(b);
    EXPECT_EQ(uri.rfind(kBundleUriPrefix, 0), 0u);
    const auto raw = encodeBundle(b);
    EXPECT_EQ(raw.size(), 2u + (1 + 4 + 1 + 12 + 2 + 32 + 4) + 32 + 136); // ~224 B (design: ~230)
    EXPECT_LT(uri.size() - std::strlen(kBundleUriPrefix), 320u);         // design: ~310 chars

    Bundle d;
    std::string err;
    ASSERT_TRUE(bundleFromText("  " + uri + "\r\n", d, err)) << err; // pasted with whitespace
    ASSERT_EQ(d.nodes.size(), 1u);
    EXPECT_EQ(d.nodes[0].id, "in-1");
    EXPECT_EQ(d.nodes[0].host, "35.200.10.20");
    EXPECT_EQ(d.nodes[0].port, 5555);
    EXPECT_EQ(0, std::memcmp(d.nodes[0].pub, b.nodes[0].pub, 32));
    EXPECT_EQ(d.nodes[0].tags, 0x101u);
    EXPECT_EQ(0, std::memcmp(d.device_sk, b.device_sk, 32));
    EXPECT_EQ(d.ticket, b.ticket);

    Bundle bare; // also accepts the base64url part alone
    ASSERT_TRUE(bundleFromText(uri.substr(std::strlen(kBundleUriPrefix)), bare, err)) << err;
}

TEST(Bundle, SeveralNodesWithDnsNames)
{
    Bundle d;
    std::string err;
    ASSERT_TRUE(bundleFromText(bundleToUri(sampleBundle(3)), d, err)) << err;
    ASSERT_EQ(d.nodes.size(), 3u);
    EXPECT_EQ(d.nodes[2].host, "vpn2.example.org");
    EXPECT_EQ(d.nodes[2].port, 5557);
}

TEST(Bundle, RejectsMalformedInput)
{
    Bundle d;
    std::string err;
    auto raw = encodeBundle(sampleBundle());
    EXPECT_FALSE(decodeBundle(raw.data(), raw.size() - 1, d, err));
    raw.push_back(0);
    EXPECT_FALSE(decodeBundle(raw.data(), raw.size(), d, err));
    EXPECT_EQ(err, "unexpected bytes after the ticket");
    raw.pop_back();
    raw[0] = 2;
    EXPECT_FALSE(decodeBundle(raw.data(), raw.size(), d, err));
    raw[0] = 1;
    raw[1] = 0; // zero nodes
    EXPECT_FALSE(decodeBundle(raw.data(), raw.size(), d, err));
    EXPECT_FALSE(bundleFromText("cppvpn://import?b=!!!", d, err));
    EXPECT_FALSE(bundleFromText("", d, err));
}
