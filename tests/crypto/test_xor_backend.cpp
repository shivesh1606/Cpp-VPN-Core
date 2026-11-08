// XorBackend: protocol v1 wire compatibility and SessionLock behaviour.
#include <gtest/gtest.h>

#include <cstring>
#include <random>
#include <vector>

#include "crypto/backends/XorBackend.h"

using namespace crypto;

namespace
{

std::unique_ptr<SessionLock> lockFor(uint8_t xor_byte)
{
    uint8_t key[kKeyBytes];
    expandV1XorKey(xor_byte, key);
    return XorBackend().newLock(key);
}

std::vector<uint8_t> randomBytes(size_t n, uint32_t seed)
{
    std::mt19937 rng(seed);
    std::vector<uint8_t> v(n);
    for (auto &b : v)
        b = static_cast<uint8_t>(rng());
    return v;
}

} // namespace

TEST(XorBackend, Metadata)
{
    XorBackend b;
    EXPECT_EQ(b.algorithmId(), kCipherXor);
    EXPECT_STREQ(b.algorithmName(), "xor");
    EXPECT_STREQ(b.implName(), "builtin");
    EXPECT_TRUE(b.insecure());
}

TEST(XorBackend, OverheadIsZero)
{
    EXPECT_EQ(lockFor(0x5a)->overhead(), 0u);
}

// Known vector: first bytes of an IPv4/ICMP header XOR 0x5a.
TEST(XorBackend, KnownVector)
{
    const uint8_t in[] = {0x45, 0x00, 0x00, 0x54, 0xff};
    const uint8_t expected[] = {0x1f, 0x5a, 0x5a, 0x0e, 0xa5};
    uint8_t out[sizeof(in)] = {};
    lockFor(0x5a)->seal(0, nullptr, 0, in, sizeof(in), out);
    EXPECT_EQ(0, std::memcmp(out, expected, sizeof(expected)));
}

// Byte-identical to the removed XorCipher::crypt (result[i] = data[i] ^ xorkey), so v1 clients
// (Android, Windows) interoperate unchanged.
TEST(XorBackend, MatchesLegacyXorCipherForAllKeys)
{
    const auto in = randomBytes(1400, 1);
    std::vector<uint8_t> out(in.size()), legacy(in.size());
    for (int k = 0; k < 256; k++)
    {
        for (size_t i = 0; i < in.size(); i++)
            legacy[i] = in[i] ^ static_cast<uint8_t>(k);
        lockFor(static_cast<uint8_t>(k))->seal(0, nullptr, 0, in.data(), in.size(), out.data());
        ASSERT_EQ(out, legacy) << "key " << k;
    }
}

TEST(XorBackend, RoundTripVariousSizes)
{
    auto lock = lockFor(0xa7);
    for (size_t len : {size_t(0), size_t(1), size_t(20), size_t(1400), size_t(1995)})
    {
        const auto in = randomBytes(len, static_cast<uint32_t>(len) + 7);
        std::vector<uint8_t> ct(len), pt(len);
        lock->seal(0, nullptr, 0, in.data(), len, ct.data());
        ASSERT_TRUE(lock->open(0, nullptr, 0, ct.data(), len, pt.data()));
        EXPECT_EQ(pt, in) << "len " << len;
    }
}

TEST(XorBackend, InPlaceOperation)
{
    auto in = randomBytes(64, 3);
    auto buf = in;
    auto lock = lockFor(0x11);
    lock->seal(0, nullptr, 0, buf.data(), buf.size(), buf.data());
    EXPECT_NE(buf, in);
    ASSERT_TRUE(lock->open(0, nullptr, 0, buf.data(), buf.size(), buf.data()));
    EXPECT_EQ(buf, in);
}

// XOR has no integrity: open() cannot detect tampering. Documents why v1 is insecure
// (design 01, section 1) and why AEAD backends must return false instead.
TEST(XorBackend, OpenCannotDetectTampering)
{
    auto lock = lockFor(0x33);
    uint8_t in[8] = {1, 2, 3, 4, 5, 6, 7, 8}, ct[8], pt[8];
    lock->seal(0, nullptr, 0, in, 8, ct);
    ct[0] ^= 0xff;
    EXPECT_TRUE(lock->open(0, nullptr, 0, ct, 8, pt));
    EXPECT_NE(pt[0], in[0]);
}

TEST(XorBackend, OnlyFirstKeyByteMatters)
{
    uint8_t k1[kKeyBytes] = {0x42}, k2[kKeyBytes];
    std::memset(k2, 0xee, sizeof(k2));
    k2[0] = 0x42;
    XorBackend b;
    uint8_t in[4] = {9, 8, 7, 6}, o1[4], o2[4];
    b.newLock(k1)->seal(0, nullptr, 0, in, 4, o1);
    b.newLock(k2)->seal(0, nullptr, 0, in, 4, o2);
    EXPECT_EQ(0, std::memcmp(o1, o2, 4));
}

TEST(XorBackend, CounterAndAadAreIgnored)
{
    auto lock = lockFor(0x77);
    const uint8_t aad[3] = {1, 2, 3};
    uint8_t in[4] = {1, 2, 3, 4}, a[4], b[4];
    lock->seal(0, nullptr, 0, in, 4, a);
    lock->seal(12345, aad, sizeof(aad), in, 4, b);
    EXPECT_EQ(0, std::memcmp(a, b, 4));
}

TEST(ExpandV1XorKey, LayoutIsByteThenZeros)
{
    uint8_t key[kKeyBytes];
    std::memset(key, 0xcc, sizeof(key));
    expandV1XorKey(0x9d, key);
    EXPECT_EQ(key[0], 0x9d);
    for (size_t i = 1; i < kKeyBytes; i++)
        EXPECT_EQ(key[i], 0) << "index " << i;
}
