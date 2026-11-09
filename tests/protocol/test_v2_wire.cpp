// Protocol v2 wire format (design 02 section 3) and the replay window (design 01 C6).
#include <gtest/gtest.h>

#include <random>
#include <set>

#include "protocol/v2/ReplayWindow.h"
#include "protocol/v2/Wire.h"

using namespace v2;

TEST(V2Wire, SizesMatchTheDesign)
{
    EXPECT_EQ(kRespLen, 97u);          // section 3.2: HS_RESP = 97 B
    EXPECT_EQ(kAckLen, 38u);           // ACK = 14 + 8 + 16
    EXPECT_EQ(kTransportMinLen, 30u);  // KEEPALIVE / BYE
    EXPECT_EQ(kInitMinLen, 6u + 96u + 15u + 32u); // header + Noise + empty payload1 + macs
    // A typical msg1 (2 ciphers, no ticket) is 151 B, with a 136 B ticket 287 B (~290 in the design)
    EXPECT_EQ(kInitMinLen + 2, 151u);
    EXPECT_EQ(kInitMinLen + 2 + 136, 287u);
    EXPECT_LT(kRespLen, kInitMinLen + 1); // no reflection amplification (G9)
    EXPECT_NE(kVersion, 1);
    EXPECT_GT(kVersion, 6); // never a v1 type byte
}

TEST(V2Wire, LittleEndianHelpersAndTransportHeader)
{
    uint8_t b[kTransportMinLen] = {0};
    writeTransportHeader(b, kData, 0x11223344u, 0x0102030405060708ull);
    const uint8_t expected[14] = {0x20, 4, 0x44, 0x33, 0x22, 0x11, 8, 7, 6, 5, 4, 3, 2, 1};
    EXPECT_EQ(0, std::memcmp(b, expected, 14));
    TransportHeader h;
    ASSERT_TRUE(readTransportHeader(b, sizeof(b), h));
    EXPECT_EQ(h.type, kData);
    EXPECT_EQ(h.receiver_idx, 0x11223344u);
    EXPECT_EQ(h.counter, 0x0102030405060708ull);

    EXPECT_FALSE(readTransportHeader(b, kTransportMinLen - 1, h)); // shorter than header + tag
    b[0] = 0x21;
    EXPECT_FALSE(readTransportHeader(b, sizeof(b), h));
    b[0] = kVersion;
    for (uint8_t t : {uint8_t(kHsInit), uint8_t(kHsResp), uint8_t(kCookieReply), uint8_t(0), uint8_t(99)})
    {
        b[1] = t;
        EXPECT_FALSE(readTransportHeader(b, sizeof(b), h)) << int(t);
    }
}

TEST(V2Wire, Tai64nEncodingAndOrdering)
{
    uint8_t a[kTai64nLen], b[kTai64nLen];
    tai64n(0, 0, a); // Unix epoch: label 2^62
    const uint8_t epoch[kTai64nLen] = {0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    EXPECT_EQ(0, std::memcmp(a, epoch, kTai64nLen));

    tai64n(1700000000, 999999999, a);
    tai64n(1700000001, 0, b);
    EXPECT_LT(compareTai64n(a, b), 0); // big-endian: byte order is time order
    tai64n(1700000001, 1, a);
    EXPECT_GT(compareTai64n(a, b), 0);
    tai64nNow(a);
    tai64n(1700000000, 0, b);
    EXPECT_GT(compareTai64n(a, b), 0);
}

TEST(V2Wire, Mac1CoversEverythingBeforeIt)
{
    uint8_t pub[32] = {7}, key[32], other_key[32];
    mac1Key(pub, key);
    pub[0] = 8;
    mac1Key(pub, other_key);

    std::vector<uint8_t> pkt(100, 0xab);
    computeMac1(key, pkt.data(), pkt.size() - kMacsLen, pkt.data() + pkt.size() - kMacsLen);
    EXPECT_TRUE(verifyMac1(key, pkt.data(), pkt.size()));
    EXPECT_FALSE(verifyMac1(other_key, pkt.data(), pkt.size())); // keyed by the receiver's key

    auto bad = pkt;
    bad[0] ^= 1;
    EXPECT_FALSE(verifyMac1(key, bad.data(), bad.size()));
    bad = pkt;
    bad[pkt.size() - kMacsLen] ^= 1; // mac1 itself
    EXPECT_FALSE(verifyMac1(key, bad.data(), bad.size()));
    bad = pkt;
    bad.back() ^= 1; // mac2 is not covered by mac1 (reserved for cookies)
    EXPECT_TRUE(verifyMac1(key, bad.data(), bad.size()));
    EXPECT_FALSE(verifyMac1(key, pkt.data(), kMacsLen - 1));
}

TEST(V2Wire, Payload1RoundTripAndStrictBounds)
{
    Payload1 p;
    tai64n(1700000000, 5, p.ts);
    p.offer = {1, 2};
    p.ticket = std::vector<uint8_t>(136, 0x5a);
    const auto enc = encodePayload1(p);
    EXPECT_EQ(enc.size(), 12u + 1 + 2 + 2 + 136);
    Payload1 d;
    ASSERT_TRUE(decodePayload1(enc.data(), enc.size(), d));
    EXPECT_EQ(0, std::memcmp(d.ts, p.ts, kTai64nLen));
    EXPECT_EQ(d.offer, p.offer);
    EXPECT_EQ(d.ticket, p.ticket);

    auto trailing = enc;
    trailing.push_back(0);
    EXPECT_FALSE(decodePayload1(trailing.data(), trailing.size(), d));
    EXPECT_FALSE(decodePayload1(enc.data(), enc.size() - 1, d)); // ticket truncated
    Payload1 empty_offer = p;
    empty_offer.offer.clear();
    auto e = encodePayload1(empty_offer);
    EXPECT_FALSE(decodePayload1(e.data(), e.size(), d));
    Payload1 many = p;
    many.offer.assign(kMaxOffer + 1, 1);
    e = encodePayload1(many);
    EXPECT_FALSE(decodePayload1(e.data(), e.size(), d));
    Payload1 big = p;
    big.ticket.assign(kMaxTicket + 1, 0);
    e = encodePayload1(big);
    EXPECT_FALSE(decodePayload1(e.data(), e.size(), d));
}

TEST(V2Wire, Payload2RoundTripWithNetworkOrderIp)
{
    Payload2 p{0x0A080002u, 1, 15}; // 10.8.0.2
    uint8_t b[kPayload2Len];
    encodePayload2(p, b);
    EXPECT_EQ(b[0], 10);
    EXPECT_EQ(b[3], 2);
    Payload2 d;
    ASSERT_TRUE(decodePayload2(b, sizeof(b), d));
    EXPECT_EQ(d.tun_ip, p.tun_ip);
    EXPECT_EQ(d.cipher_id, 1);
    EXPECT_EQ(d.keepalive_s, 15);
    EXPECT_FALSE(decodePayload2(b, sizeof(b) - 1, d));
}

// ---------------- ReplayWindow ----------------

TEST(ReplayWindow, InOrderDuplicatesAndReordering)
{
    ReplayWindow w;
    EXPECT_TRUE(w.check(0));
    w.update(0); // ACK uses counter 0
    EXPECT_FALSE(w.check(0));
    for (uint64_t c = 1; c <= 100; c++)
    {
        ASSERT_TRUE(w.check(c));
        w.update(c);
    }
    EXPECT_FALSE(w.check(50));
    EXPECT_TRUE(w.check(150));
    w.update(150);
    EXPECT_TRUE(w.check(120)); // late but inside the window
    w.update(120);
    EXPECT_FALSE(w.check(120));
}

TEST(ReplayWindow, TooOldAndBigJumps)
{
    ReplayWindow w;
    w.update(5000);
    EXPECT_FALSE(w.check(5000 - ReplayWindow::kWindow)); // exactly the window size behind
    EXPECT_TRUE(w.check(5000 - ReplayWindow::kWindow + 1));
    w.update(1000000); // jump far ahead clears the whole ring
    EXPECT_FALSE(w.check(5000));
    EXPECT_TRUE(w.check(1000000 - 5));
}

// Compare against a simple model (std::set) over random traffic with reordering and duplicates.
TEST(ReplayWindow, MatchesReferenceModel)
{
    std::mt19937_64 rng(12345);
    ReplayWindow w;
    std::set<uint64_t> seen;
    uint64_t top = 0;
    bool any = false;
    for (int i = 0; i < 200000; i++)
    {
        const uint64_t base = any ? top : 0;
        const uint64_t c = (rng() % 4 == 0 && base > 2500) ? base - rng() % 2500 // old / reordered
                                                           : base + rng() % 70;   // mostly forward
        const bool expect = !any || c > top || (top - c < ReplayWindow::kWindow && !seen.count(c));
        ASSERT_EQ(w.check(c), expect) << "i=" << i << " c=" << c << " top=" << top;
        if (expect)
        {
            w.update(c);
            seen.insert(c);
            if (!any || c > top)
                top = c;
            any = true;
        }
    }
}
