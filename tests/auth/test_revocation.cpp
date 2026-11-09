// Revocation list (design 03 section 6): format, signature, no rollback.
#include <gtest/gtest.h>

#include "auth/RevocationList.h"
#include "ticket_fixture.h"

using namespace auth;

namespace
{
RevocationList sample(uint8_t key_id, uint64_t seq)
{
    RevocationList l;
    l.key_id = key_id;
    l.seq = seq;
    l.issued_at = 1800000000;
    const uint8_t u[16] = {1, 2, 3};
    l.addUser(u);
    l.addTicket(0x0102030405060708ull);
    l.addTicket(99);
    return l;
}
} // namespace

TEST(RevocationList, RoundTripAndLayout)
{
    TestIssuer iss;
    const auto bytes = sample(1, 7).encodeSigned(iss.sk);
    EXPECT_EQ(bytes.size(), 18u + 3 * 17 + 64);
    EXPECT_EQ(bytes[0], kRevocationVersion);
    EXPECT_EQ(bytes[1], 1);
    EXPECT_EQ(bytes[2], 7); // seq u64 LE
    EXPECT_EQ(bytes[14], 3); // count

    RevocationList l;
    ASSERT_EQ(parseRevocationList(bytes.data(), bytes.size(), iss.keys(), l), ListVerdict::kOk);
    EXPECT_EQ(l.seq, 7u);
    EXPECT_EQ(l.issued_at, 1800000000u);
    const uint8_t u[16] = {1, 2, 3}, other[16] = {9};
    EXPECT_TRUE(l.hasUser(u));
    EXPECT_FALSE(l.hasUser(other));
    EXPECT_TRUE(l.hasTicket(0x0102030405060708ull));
    EXPECT_TRUE(l.hasTicket(99));
    EXPECT_FALSE(l.hasTicket(100));
    EXPECT_EQ(sample(1, 7).encodeSigned(iss.sk), bytes) << "encoding must be deterministic";
}

TEST(RevocationList, RejectsTamperingWrongKeyAndBadFormat)
{
    TestIssuer iss, other;
    const auto good = sample(1, 1).encodeSigned(iss.sk);
    RevocationList l;
    for (size_t pos : {size_t(2), size_t(20), good.size() - 1})
    {
        auto bad = good;
        bad[pos] ^= 1;
        EXPECT_EQ(parseRevocationList(bad.data(), bad.size(), iss.keys(), l), ListVerdict::kSig) << pos;
    }
    EXPECT_EQ(parseRevocationList(good.data(), good.size(), other.keys(), l), ListVerdict::kSig);
    const IssuerKeys none;
    EXPECT_EQ(parseRevocationList(good.data(), good.size(), none, l), ListVerdict::kUnknownKey);
    EXPECT_EQ(parseRevocationList(good.data(), good.size() - 1, iss.keys(), l), ListVerdict::kFormat);
    auto count = good;
    count[14] = 4; // count no longer matches the length
    EXPECT_EQ(parseRevocationList(count.data(), count.size(), iss.keys(), l), ListVerdict::kFormat);
    EXPECT_EQ(parseRevocationList(nullptr, 0, iss.keys(), l), ListVerdict::kFormat);

    // An empty signed list is valid (published before anyone was revoked)
    RevocationList empty;
    empty.key_id = 1;
    auto e = empty.encodeSigned(iss.sk);
    EXPECT_EQ(parseRevocationList(e.data(), e.size(), iss.keys(), l), ListVerdict::kOk);
    EXPECT_EQ(l.size(), 0u);
}

TEST(RevocationState, OnlyNewerSignedListsReplaceTheCurrentOne)
{
    TestIssuer iss;
    RevocationState st;
    EXPECT_EQ(st.current(), nullptr);
    const auto v5 = sample(1, 5).encodeSigned(iss.sk);
    const auto v4 = sample(1, 4).encodeSigned(iss.sk);
    const auto v6 = sample(1, 6).encodeSigned(iss.sk);
    ASSERT_EQ(st.update(v5.data(), v5.size(), iss.keys()), ListVerdict::kOk);
    EXPECT_EQ(st.current()->seq, 5u);
    EXPECT_EQ(st.update(v5.data(), v5.size(), iss.keys()), ListVerdict::kRollback); // same seq
    EXPECT_EQ(st.update(v4.data(), v4.size(), iss.keys()), ListVerdict::kRollback); // older: replayed old list
    EXPECT_EQ(st.current()->seq, 5u);
    auto forged = v6;
    forged[30] ^= 1;
    EXPECT_EQ(st.update(forged.data(), forged.size(), iss.keys()), ListVerdict::kSig);
    EXPECT_EQ(st.current()->seq, 5u) << "a bad list keeps the last good one";
    EXPECT_EQ(st.update(v6.data(), v6.size(), iss.keys()), ListVerdict::kOk);
    EXPECT_EQ(st.current()->seq, 6u);
}
