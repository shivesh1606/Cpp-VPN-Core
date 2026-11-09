// auth.mode = ticket end to end in process: v2::Client <-> v2::Server + auth::TicketAuthenticator
// (design 03 sections 2.1, 2.2, 6). Each rejected ticket moves exactly one drop counter.
#include <gtest/gtest.h>

#include <set>

#include "../auth/ticket_fixture.h"
#include "auth/RevocationList.h"
#include "auth/TicketAuthenticator.h"
#include "protocol/v2/Client.h"
#include "protocol/v2/Server.h"

using namespace v2;

namespace
{

class Pool : public IpPool
{
public:
    uint32_t allocate() override
    {
        for (uint32_t ip = 0x0A080002u; ip < 0x0A080010u; ip++)
            if (!used.count(ip))
            {
                used.insert(ip);
                return ip;
            }
        return 0;
    }
    void activate(uint32_t) override {}
    void release(uint32_t ip) override { used.erase(ip); }
    std::set<uint32_t> used;
};

uint64_t allDrops(const ServerStats &s)
{
    uint64_t n = s.hs_drop_format + s.hs_drop_mac1 + s.hs_drop_decrypt + s.hs_drop_auth + s.hs_drop_replay +
                 s.hs_drop_no_cipher + s.hs_drop_pool_empty;
    for (uint64_t c : s.hs_drop_ticket)
        n += c;
    return n;
}

class V2Tickets : public testing::Test
{
protected:
    static constexpr uint32_t kNodeMask = 0b1; // node carries tag bit 0 ("friends")

    void SetUp() override
    {
        crypto::sodiumReady();
        randombytes_buf(node_sk_, 32);
        crypto_scalarmult_base(node_pk_, node_sk_);
        randombytes_buf(dev_sk_, 32);
        crypto_scalarmult_base(dev_pk_, dev_sk_);
        authn_ = std::make_unique<auth::TicketAuthenticator>(issuer_.keys(), kNodeMask, [this] { return unix_; });
        ServerConfig cfg;
        cfg.auth = ServerConfig::kTicket;
        cfg.authenticator = authn_.get();
        server_ = std::make_unique<Server>(node_sk_, cfg, pool_);
    }

    std::unique_ptr<Client> client(const std::vector<uint8_t> &ticket, const uint8_t *sk = nullptr)
    {
        ClientConfig cc;
        std::memcpy(cc.static_priv, sk ? sk : dev_sk_, 32);
        std::memcpy(cc.server_pub, node_pk_, 32);
        cc.ticket = ticket;
        return std::make_unique<Client>(cc);
    }
    std::vector<uint8_t> validTicket(uint32_t tags = 1) { return issuer_.bytes(issuer_.ticket(dev_pk_, unix_, tags)); }

    // HS_INIT -> server; on HS_RESP completes the handshake and delivers the ACK.
    bool connect(Client &c)
    {
        uint8_t init[kInitMaxLen], reply[kRespLen], plain[2048], ack[kAckLen];
        size_t rl = 0, pl = 0, al = 0;
        const size_t n = c.startHandshake(now_ms_, init);
        if (server_->receive(init, n, ep_, now_ms_, reply, rl, plain, pl) != Server::Rx::kReply)
            return false;
        if (c.receive(reply, rl, now_ms_, ack, al, plain, pl) != Client::Event::kEstablished)
            return false;
        return server_->receive(ack, al, ep_, now_ms_, reply, rl, plain, pl) == Server::Rx::kConsumed;
    }
    // Expects the handshake to be dropped with exactly ticket reason `reason`.
    void expectRejected(Client &c, auth::Verdict reason, const char *what)
    {
        const ServerStats before = server_->stats();
        EXPECT_FALSE(connect(c)) << what;
        const ServerStats &after = server_->stats();
        EXPECT_EQ(after.hs_drop_ticket[size_t(reason)], before.hs_drop_ticket[size_t(reason)] + 1) << what;
        EXPECT_EQ(allDrops(after), allDrops(before) + 1) << what << ": more than one counter moved";
        EXPECT_TRUE(pool_.used.empty()) << what << ": IP allocated for a rejected ticket";
        unix_ += 1; // next attempt has a newer TAI64N timestamp than any accepted one
        now_ms_ += 1000;
    }

    TestIssuer issuer_;
    uint8_t node_sk_[32], node_pk_[32], dev_sk_[32], dev_pk_[32];
    uint64_t unix_ = 1800000000, now_ms_ = 5000000;
    Pool pool_;
    Endpoint ep_{0x01020304, 4000};
    std::unique_ptr<auth::TicketAuthenticator> authn_;
    std::unique_ptr<Server> server_;
};

} // namespace

TEST_F(V2Tickets, ValidTicketConnects)
{
    auto c = client(validTicket());
    ASSERT_TRUE(connect(*c));
    EXPECT_EQ(server_->activeSessions(), 1u);
    EXPECT_EQ(allDrops(server_->stats()), 0u);
}

TEST_F(V2Tickets, EveryFailureReasonHasItsOwnCounter)
{
    auto none = client({});
    expectRejected(*none, auth::Verdict::kFormat, "no ticket");

    TestIssuer stranger(9); // key_id 9 is not configured on the node
    auto unknown = client(stranger.bytes(stranger.ticket(dev_pk_, unix_)));
    expectRejected(*unknown, auth::Verdict::kUnknownKey, "unknown issuer key");

    auto forged_bytes = validTicket();
    forged_bytes[52] ^= 0b10; // grant itself another tag
    auto forged = client(forged_bytes);
    expectRejected(*forged, auth::Verdict::kSig, "modified ticket");

    auth::Ticket old = issuer_.ticket(dev_pk_, unix_);
    old.nbf = uint32_t(unix_ - 7200);
    old.exp = uint32_t(unix_ - 3600);
    auth::sign(old, issuer_.sk);
    auto expired = client(issuer_.bytes(old));
    expectRejected(*expired, auth::Verdict::kExpired, "expired ticket");

    auto scope = client(validTicket(0b100)); // tag the node does not carry
    expectRejected(*scope, auth::Verdict::kScope, "out of scope");

    uint8_t thief_sk[32];
    randombytes_buf(thief_sk, 32);
    auto stolen = client(validTicket(), thief_sk); // someone else's ticket on another device
    expectRejected(*stolen, auth::Verdict::kDevice, "ticket of another device");

    auth::RevocationList l;
    l.key_id = issuer_.key_id;
    l.seq = 1;
    l.addTicket(0x1122334455667788ull);
    std::vector<Server::Outgoing> out;
    size_t dropped = 0;
    ASSERT_EQ(authn_->applyRevocations(l.encodeSigned(issuer_.sk), server_.get(), now_ms_, out, dropped),
              auth::ListVerdict::kOk);
    auto revoked = client(validTicket());
    expectRejected(*revoked, auth::Verdict::kRevoked, "revoked ticket");
}

TEST_F(V2Tickets, RevocationDropsActiveSessionsWithByeAndFreesTheAddress)
{
    auto c = client(validTicket());
    ASSERT_TRUE(connect(*c));
    ASSERT_EQ(pool_.used.size(), 1u);

    auth::RevocationList l;
    l.key_id = issuer_.key_id;
    l.seq = 3;
    uint8_t user[16];
    for (int i = 0; i < 16; i++)
        user[i] = uint8_t(0xa0 + i); // fixture user id
    l.addUser(user);
    std::vector<Server::Outgoing> out;
    size_t dropped = 0;
    ASSERT_EQ(authn_->applyRevocations(l.encodeSigned(issuer_.sk), server_.get(), now_ms_, out, dropped),
              auth::ListVerdict::kOk);
    EXPECT_EQ(dropped, 1u);
    EXPECT_EQ(server_->activeSessions(), 0u);
    EXPECT_TRUE(pool_.used.empty());
    EXPECT_EQ(server_->stats().removed_revoked, 1u);
    ASSERT_EQ(out.size(), 1u);
    uint8_t ack[kAckLen], plain[256];
    size_t al = 0, pl = 0;
    EXPECT_EQ(c->receive(out[0].pkt.data(), out[0].pkt.size(), now_ms_, ack, al, plain, pl), Client::Event::kBye);

    // An older list (replay of seq 2) is ignored and drops nothing
    auth::RevocationList older;
    older.key_id = issuer_.key_id;
    older.seq = 2;
    out.clear();
    EXPECT_EQ(authn_->applyRevocations(older.encodeSigned(issuer_.sk), server_.get(), now_ms_, out, dropped),
              auth::ListVerdict::kRollback);
    EXPECT_EQ(authn_->revocations()->seq, 3u);
}

TEST_F(V2Tickets, TicketIsCheckedAgainOnRekey)
{
    auth::Ticket t = issuer_.ticket(dev_pk_, unix_);
    t.exp = uint32_t(unix_ + 100); // short ticket
    auth::sign(t, issuer_.sk);
    auto c = client(issuer_.bytes(t));
    ASSERT_TRUE(connect(*c));

    unix_ += 200; // the ticket expired (beyond the 60 s skew) while the session runs
    now_ms_ += 120000;
    const ServerStats before = server_->stats();
    EXPECT_FALSE(connect(*c)) << "rekey with an expired ticket must fail";
    EXPECT_EQ(server_->stats().hs_drop_ticket[size_t(auth::Verdict::kExpired)],
              before.hs_drop_ticket[size_t(auth::Verdict::kExpired)] + 1);
    EXPECT_EQ(server_->activeSessions(), 1u) << "the current session runs until reject-after";
    std::vector<Server::Outgoing> out;
    now_ms_ += 60000; // 180 s after the session was created
    server_->tick(now_ms_, out);
    EXPECT_EQ(server_->activeSessions(), 0u);
    EXPECT_TRUE(pool_.used.empty());
}
