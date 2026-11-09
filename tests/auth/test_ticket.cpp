// Ticket v1 (design 03 section 2): layout, signature, and every verification reason of 2.1.
#include <gtest/gtest.h>

#include "auth/RevocationList.h"
#include "auth/Ticket.h"
#include "../crypto/hex.h"
#include "ticket_fixture.h"

using namespace auth;

namespace
{
constexpr uint64_t kNow = 1800000000; // 2027-01-15
struct Device
{
    uint8_t sk[32], pk[32];
    Device()
    {
        crypto::sodiumReady();
        randombytes_buf(sk, 32);
        crypto_scalarmult_base(pk, sk);
    }
};
} // namespace

// Pins the byte layout of section 2 (the Kotlin client and any other issuer must match it).
TEST(Ticket, BodyLayoutMatchesTheDesign)
{
    Ticket t;
    t.key_id = 7;
    t.tier = 2;
    for (int i = 0; i < 16; i++)
        t.user_id[i] = uint8_t(i);
    for (int i = 0; i < 32; i++)
        t.device_pk[i] = uint8_t(0x20 + i);
    t.tags = 0x00000101;
    t.nbf = 0x11223344;
    t.exp = 0x55667788;
    t.ticket_id = 0x0102030405060708ull;
    uint8_t body[kTicketBodyLen];
    encodeBody(t, body);
    const auto expected = hex("01 07 02 00"
                              "000102030405060708090a0b0c0d0e0f"
                              "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                              "01010000" "44332211" "88776655" "0807060504030201");
    ASSERT_EQ(expected.size(), kTicketBodyLen);
    EXPECT_EQ(std::vector<uint8_t>(body, body + kTicketBodyLen), expected);
}

TEST(Ticket, SignatureCoversContextAndBody)
{
    TestIssuer iss;
    Device d;
    const Ticket t = iss.ticket(d.pk, kNow);
    const auto b = iss.bytes(t);
    // sig = Ed25519("cppvpn-ticket-v1" || bytes[0:72]) (domain separation)
    std::vector<uint8_t> msg(kTicketContext, kTicketContext + 16);
    msg.insert(msg.end(), b.begin(), b.begin() + 72);
    EXPECT_EQ(crypto_sign_verify_detached(b.data() + 72, msg.data(), msg.size(), iss.pk), 0);
    EXPECT_NE(crypto_sign_verify_detached(b.data() + 72, b.data(), 72, iss.pk), 0) << "body alone must not verify";

    Ticket d2;
    ASSERT_TRUE(decode(b.data(), b.size(), d2));
    EXPECT_EQ(d2.ticket_id, t.ticket_id);
    EXPECT_EQ(d2.exp, t.exp);
    EXPECT_EQ(0, std::memcmp(d2.device_pk, d.pk, 32));
}

TEST(Ticket, ValidTicketVerifies)
{
    TestIssuer iss;
    Device d;
    const auto b = iss.bytes(iss.ticket(d.pk, kNow));
    Ticket out;
    EXPECT_EQ(verify(b.data(), b.size(), d.pk, kNow, iss.keys(), 1, nullptr, &out), Verdict::kOk);
    EXPECT_EQ(out.ticket_id, 0x1122334455667788ull);
}

TEST(Ticket, EachFailureHasItsOwnReason)
{
    TestIssuer iss, other(1);
    Device d, d2;
    const Ticket t = iss.ticket(d.pk, kNow);
    const auto good = iss.bytes(t);
    auto v = [&](const std::vector<uint8_t> &b, uint64_t now = kNow, uint32_t mask = 1,
                 const uint8_t *s_c = nullptr, const RevocationList *r = nullptr, const IssuerKeys *k = nullptr) {
        return verify(b.data(), b.size(), s_c ? s_c : d.pk, now, k ? *k : iss.keys(), mask, r);
    };

    // FORMAT: length, version, reserved byte
    EXPECT_EQ(v(std::vector<uint8_t>(good.begin(), good.end() - 1)), Verdict::kFormat);
    auto bad = good;
    bad[0] = 2;
    EXPECT_EQ(v(bad), Verdict::kFormat);
    bad = good;
    bad[3] = 1;
    EXPECT_EQ(v(bad), Verdict::kFormat);

    // UNKNOWN_KEY: key_id not configured on the node
    const IssuerKeys none;
    EXPECT_EQ(v(good, kNow, 1, nullptr, nullptr, &none), Verdict::kUnknownKey);

    // SIG: any changed byte of the body or signature; another issuer's key
    for (size_t pos : {size_t(1), size_t(10), size_t(30), size_t(53), size_t(60), size_t(70), size_t(100)})
    {
        bad = good;
        bad[pos] ^= 1;
        const Verdict r = v(bad);
        EXPECT_TRUE(r == Verdict::kSig || (pos == 1 && r == Verdict::kUnknownKey)) << "byte " << pos;
    }
    const IssuerKeys others = other.keys();
    EXPECT_EQ(v(good, kNow, 1, nullptr, nullptr, &others), Verdict::kSig);

    // EXPIRED with the +-60 s skew of section 2: nbf - 60 <= now < exp + 60
    EXPECT_EQ(v(good, t.nbf - 60), Verdict::kOk);
    EXPECT_EQ(v(good, t.nbf - 61), Verdict::kExpired);
    EXPECT_EQ(v(good, uint64_t(t.exp) + 59), Verdict::kOk);
    EXPECT_EQ(v(good, uint64_t(t.exp) + 60), Verdict::kExpired);

    // SCOPE: no tag in common with the node
    EXPECT_EQ(v(good, kNow, 0b10), Verdict::kScope);
    EXPECT_EQ(v(good, kNow, 0b11), Verdict::kOk);

    // DEVICE: presented by another client key
    EXPECT_EQ(v(good, kNow, 1, d2.pk), Verdict::kDevice);

    // REVOKED: by user id or by ticket id
    RevocationList by_user, by_ticket, unrelated;
    by_user.addUser(t.user_id);
    by_ticket.addTicket(t.ticket_id);
    unrelated.addTicket(42);
    EXPECT_EQ(v(good, kNow, 1, nullptr, &by_user), Verdict::kRevoked);
    EXPECT_EQ(v(good, kNow, 1, nullptr, &by_ticket), Verdict::kRevoked);
    EXPECT_EQ(v(good, kNow, 1, nullptr, &unrelated), Verdict::kOk);
}

TEST(Ticket, ChecksRunInDesignOrder)
{
    // An expired ticket for the wrong device and the wrong scope reports EXPIRED (checked first),
    // so the counters tell an operator the most basic problem.
    TestIssuer iss;
    Device d, d2;
    const auto b = iss.bytes(iss.ticket(d.pk, kNow));
    EXPECT_EQ(verify(b.data(), b.size(), d2.pk, kNow + 999999, iss.keys(), 0b100, nullptr), Verdict::kExpired);
    EXPECT_STREQ(verdictName(Verdict::kScope), "scope");
}

TEST(Ticket, KeyRotationUsesKeyId)
{
    TestIssuer old_key(1), new_key(2);
    Device d;
    IssuerKeys both = old_key.keys();
    const IssuerKeys added = new_key.keys(); // one map: begin() and end() must come from the same object
    both.insert(added.begin(), added.end());
    const auto t_old = old_key.bytes(old_key.ticket(d.pk, kNow));
    const auto t_new = new_key.bytes(new_key.ticket(d.pk, kNow));
    EXPECT_EQ(verify(t_old.data(), t_old.size(), d.pk, kNow, both, 1, nullptr), Verdict::kOk);
    EXPECT_EQ(verify(t_new.data(), t_new.size(), d.pk, kNow, both, 1, nullptr), Verdict::kOk);
    EXPECT_EQ(verify(t_old.data(), t_old.size(), d.pk, kNow, new_key.keys(), 1, nullptr), Verdict::kUnknownKey);
}
