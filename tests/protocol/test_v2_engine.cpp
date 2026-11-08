// Protocol v2 engines end to end, in process: v2::Client <-> v2::Server (design 02 sections 4-8).
// Verification section 10.3: every rejected HS_INIT increments exactly one drop counter.
#include <gtest/gtest.h>

#include <sodium.h>

#include <set>

#include "crypto/CipherRegistry.h"
#include "crypto/backends/SodiumAead.h"
#include "protocol/v2/Client.h"
#include "protocol/v2/Server.h"

using namespace v2;

namespace
{

constexpr uint64_t kSec = 1000;

class FakePool : public IpPool
{
public:
    explicit FakePool(uint32_t size, uint32_t first = 0x0A080002u)
    {
        for (uint32_t i = 0; i < size; i++)
            free_.insert(first + i);
    }
    uint32_t allocate() override
    {
        if (free_.empty())
            return 0;
        const uint32_t ip = *free_.begin();
        free_.erase(free_.begin());
        allocations++;
        return ip;
    }
    void activate(uint32_t ip) override { active.insert(ip); }
    void release(uint32_t ip) override
    {
        active.erase(ip);
        free_.insert(ip);
        releases++;
    }
    size_t freeCount() const { return free_.size(); }
    int allocations = 0, releases = 0;
    std::set<uint32_t> active;

private:
    std::set<uint32_t> free_;
};

struct Keys
{
    uint8_t priv[32], pub[32];
    Keys()
    {
        crypto::sodiumReady();
        randombytes_buf(priv, 32);
        crypto_scalarmult_base(pub, priv);
    }
    std::string pubStr() const { return std::string(reinterpret_cast<const char *>(pub), 32); }
};

// IPv4 header (20 B) + payload, with the given source address (host order).
std::vector<uint8_t> ipPacket(uint32_t src, uint32_t dst, size_t payload = 40, uint8_t fill = 0x11)
{
    std::vector<uint8_t> p(20 + payload, fill);
    p[0] = 0x45;
    for (int i = 0; i < 4; i++)
    {
        p[12 + i] = uint8_t(src >> (24 - 8 * i));
        p[16 + i] = uint8_t(dst >> (24 - 8 * i));
    }
    return p;
}

uint64_t hsDrops(const ServerStats &s)
{
    return s.hs_drop_format + s.hs_drop_mac1 + s.hs_drop_decrypt + s.hs_drop_auth + s.hs_drop_replay +
           s.hs_drop_no_cipher + s.hs_drop_pool_empty;
}

class V2Engine : public testing::Test
{
protected:
    V2Engine() : pool_(10) {}

    void SetUp() override { makeServer(ServerConfig{}); }

    void makeServer(ServerConfig cfg, bool allow_client = true)
    {
        if (allow_client)
            cfg.allowed.insert(client_keys_.pubStr());
        server_ = std::make_unique<Server>(server_keys_.priv, cfg, pool_);
    }
    std::unique_ptr<Client> makeClient(const Keys &k, std::vector<uint8_t> offer = {1, 2})
    {
        ClientConfig cc;
        std::memcpy(cc.static_priv, k.priv, 32);
        std::memcpy(cc.server_pub, server_keys_.pub, 32);
        cc.offer = std::move(offer);
        return std::make_unique<Client>(cc);
    }

    Server::Rx toServer(const uint8_t *p, size_t n, const Endpoint &from = Endpoint{0x01020304, 4000})
    {
        reply_len_ = plain_len_ = 0;
        return server_->receive(p, n, from, now_, reply_, reply_len_, plain_, plain_len_);
    }
    Server::Rx toServer(const std::vector<uint8_t> &v, const Endpoint &from = Endpoint{0x01020304, 4000})
    {
        return toServer(v.data(), v.size(), from);
    }
    Client::Event toClient(Client &c, const uint8_t *p, size_t n)
    {
        cout_len_ = cplain_len_ = 0;
        return c.receive(p, n, now_, cout_, cout_len_, cplain_, cplain_len_);
    }
    std::vector<uint8_t> init(Client &c)
    {
        uint8_t b[kInitMaxLen];
        const size_t n = c.startHandshake(now_, b);
        EXPECT_GT(n, 0u);
        return std::vector<uint8_t>(b, b + n);
    }
    // HS_INIT -> HS_RESP -> ACK (optionally not delivered). Returns the ACK.
    std::vector<uint8_t> connect(Client &c, bool deliver_ack = true)
    {
        EXPECT_EQ(toServer(init(c)), Server::Rx::kReply);
        EXPECT_EQ(reply_len_, kRespLen);
        EXPECT_EQ(toClient(c, reply_, reply_len_), Client::Event::kEstablished);
        std::vector<uint8_t> ack(cout_, cout_ + cout_len_);
        EXPECT_EQ(ack.size(), kAckLen);
        if (deliver_ack)
        {
            EXPECT_EQ(toServer(ack), Server::Rx::kConsumed);
        }
        return ack;
    }
    std::vector<uint8_t> dataFrom(Client &c, uint32_t src)
    {
        const auto ip = ipPacket(src, 0x0A080001u);
        std::vector<uint8_t> out(ip.size() + kTransportMinLen);
        out.resize(c.sealData(ip.data(), ip.size(), now_, out.data()));
        return out;
    }

    Keys server_keys_, client_keys_;
    FakePool pool_;
    std::unique_ptr<Server> server_;
    uint64_t now_ = 1000 * kSec;
    uint8_t reply_[kRespLen], plain_[2048], cout_[kAckLen], cplain_[2048];
    size_t reply_len_ = 0, plain_len_ = 0, cout_len_ = 0, cplain_len_ = 0;
};

} // namespace

TEST_F(V2Engine, HandshakeAckAndDataInBothDirections)
{
    auto c = makeClient(client_keys_);
    const auto msg1 = init(*c);
    EXPECT_EQ(msg1.size(), 151u); // 2 ciphers, no ticket
    ASSERT_EQ(toServer(msg1), Server::Rx::kReply);
    EXPECT_EQ(server_->pendingSessions(), 1u);
    EXPECT_TRUE(pool_.active.empty()) << "IP must not be ACTIVE before confirmation";

    ASSERT_EQ(toClient(*c, reply_, reply_len_), Client::Event::kEstablished);
    EXPECT_EQ(c->tunIp(), 0x0A080002u);
    EXPECT_EQ(c->cipherId(), crypto::kCipherChaCha20Poly1305); // server default preference
    EXPECT_EQ(c->keepaliveSeconds(), 15);
    EXPECT_EQ(c->handshakeId().size(), 16u);

    ASSERT_EQ(toServer(cout_, cout_len_), Server::Rx::kConsumed); // ACK
    EXPECT_EQ(server_->stats().hs_confirm_ack, 1u);
    EXPECT_EQ(server_->activeSessions(), 1u);
    EXPECT_EQ(pool_.active.count(0x0A080002u), 1u);

    // client -> server
    const auto ip = ipPacket(0x0A080002u, 0x08080808u, 100, 0x77);
    uint8_t wire[2048];
    size_t n = c->sealData(ip.data(), ip.size(), now_, wire);
    EXPECT_EQ(n, ip.size() + 30);
    ASSERT_EQ(toServer(wire, n), Server::Rx::kDeliver);
    EXPECT_EQ(std::vector<uint8_t>(plain_, plain_ + plain_len_), ip);

    // server -> client
    const auto back = ipPacket(0x08080808u, 0x0A080002u, 60, 0x33);
    Endpoint to;
    ASSERT_TRUE(server_->seal(0x0A080002u, back.data(), back.size(), now_, wire, n, to));
    EXPECT_EQ(to, (Endpoint{0x01020304, 4000}));
    ASSERT_EQ(toClient(*c, wire, n), Client::Event::kData);
    EXPECT_EQ(std::vector<uint8_t>(cplain_, cplain_ + cplain_len_), back);

    EXPECT_FALSE(server_->seal(0x0A080009u, back.data(), back.size(), now_, wire, n, to));
    EXPECT_EQ(hsDrops(server_->stats()), 0u);
}

// Section 10.3: each bad HS_INIT increments exactly one drop counter and creates no state.
TEST_F(V2Engine, EachRejectedInitIncrementsExactlyOneCounter)
{
    auto c = makeClient(client_keys_);
    uint8_t mk[32];
    mac1Key(server_keys_.pub, mk);
    auto remac = [&](std::vector<uint8_t> m) {
        computeMac1(mk, m.data(), m.size() - kMacsLen, m.data() + m.size() - kMacsLen);
        return m;
    };
    auto expectOnly = [&](const std::vector<uint8_t> &pkt, uint64_t ServerStats::*counter, const char *what) {
        const ServerStats before = server_->stats();
        EXPECT_EQ(toServer(pkt), Server::Rx::kDropped) << what;
        const ServerStats &after = server_->stats();
        EXPECT_EQ(after.*counter, before.*counter + 1) << what;
        EXPECT_EQ(hsDrops(after), hsDrops(before) + 1) << what << ": more than one counter moved";
        EXPECT_EQ(server_->pendingSessions() + server_->activeSessions(), 0u) << what;
        EXPECT_EQ(pool_.allocations, 0) << what << ": IP allocated before authentication (G7)";
    };

    const auto good = init(*c);
    expectOnly(std::vector<uint8_t>(good.begin(), good.begin() + 60), &ServerStats::hs_drop_format, "truncated");
    auto bad_mac = good;
    bad_mac[bad_mac.size() - kMacsLen] ^= 1;
    expectOnly(bad_mac, &ServerStats::hs_drop_mac1, "bad mac1");
    auto tampered = good;
    tampered[50] ^= 1; // inside enc(s), with a valid mac1 recomputed by an attacker who knows S_pub
    expectOnly(remac(tampered), &ServerStats::hs_drop_decrypt, "tampered ciphertext");
    auto low_order = good;
    std::memset(low_order.data() + kInitHeaderLen, 0, 32); // e_c = 0
    expectOnly(remac(low_order), &ServerStats::hs_drop_decrypt, "low-order e_c");

    Keys stranger;
    auto sc = makeClient(stranger);
    expectOnly(init(*sc), &ServerStats::hs_drop_auth, "client not in allowlist");

    auto nc = makeClient(client_keys_, {0x7f}); // offers only an unknown cipher id
    expectOnly(init(*nc), &ServerStats::hs_drop_no_cipher, "no cipher in common");
    auto xc = makeClient(client_keys_, {0}); // xor only, not allowed by the server
    expectOnly(init(*xc), &ServerStats::hs_drop_no_cipher, "xor without allow_insecure_xor");

    // Replay: an older timestamp than one already accepted
    const auto older = init(*c);
    now_ += 1;
    const auto newer = init(*c);
    ASSERT_EQ(toServer(newer), Server::Rx::kReply);
    const int allocs = pool_.allocations;
    const ServerStats before = server_->stats();
    EXPECT_EQ(toServer(older), Server::Rx::kDropped);
    EXPECT_EQ(server_->stats().hs_drop_replay, before.hs_drop_replay + 1);
    EXPECT_EQ(hsDrops(server_->stats()), hsDrops(before) + 1);
    EXPECT_EQ(pool_.allocations, allocs);
}

TEST_F(V2Engine, EmptyPoolIsTheOnlyFailureAfterAuthentication)
{
    FakePool empty(0);
    ServerConfig cfg;
    cfg.allowed.insert(client_keys_.pubStr());
    Server s(server_keys_.priv, cfg, empty);
    auto c = makeClient(client_keys_);
    const auto m = init(*c);
    size_t rl, pl;
    EXPECT_EQ(s.receive(m.data(), m.size(), Endpoint{}, now_, reply_, rl, plain_, pl), Server::Rx::kDropped);
    EXPECT_EQ(s.stats().hs_drop_pool_empty, 1u);
    EXPECT_EQ(hsDrops(s.stats()), 1u);
}

TEST_F(V2Engine, ReplayOfAnExpiredHandshakeIsRejected)
{
    auto c = makeClient(client_keys_);
    const auto m = init(*c);
    ASSERT_EQ(toServer(m), Server::Rx::kReply);
    std::vector<Server::Outgoing> out;
    now_ += 10 * kSec;
    server_->tick(now_, out); // pending expires, msg2 cache entry with it
    EXPECT_EQ(server_->stats().hs_expired, 1u);
    EXPECT_EQ(toServer(m), Server::Rx::kDropped); // same ts again: replay, not a cached resend
    EXPECT_EQ(server_->stats().hs_drop_replay, 1u);
}

TEST_F(V2Engine, RetransmittedInitGetsTheCachedResponseWithoutNewState)
{
    auto c = makeClient(client_keys_);
    const auto m = init(*c);
    ASSERT_EQ(toServer(m), Server::Rx::kReply);
    const std::vector<uint8_t> first(reply_, reply_ + reply_len_);
    ASSERT_EQ(toServer(m, Endpoint{0x05060708, 5000}), Server::Rx::kReply); // even from a new port
    EXPECT_EQ(std::vector<uint8_t>(reply_, reply_ + reply_len_), first);
    EXPECT_EQ(server_->stats().hs_retransmit, 1u);
    EXPECT_EQ(server_->pendingSessions(), 1u);
    EXPECT_EQ(pool_.allocations, 1);
}

TEST_F(V2Engine, NewerHandshakeReplacesPendingOneAndKeepsTheAddress)
{
    auto c = makeClient(client_keys_);
    ASSERT_EQ(toServer(init(*c)), Server::Rx::kReply);
    now_ += 5 * kSec; // client retry: new msg1, new ts
    ASSERT_EQ(toServer(init(*c)), Server::Rx::kReply);
    EXPECT_EQ(server_->stats().hs_replaced, 1u);
    EXPECT_EQ(server_->pendingSessions(), 1u);
    EXPECT_EQ(pool_.allocations, 1);
    EXPECT_EQ(pool_.releases, 0) << "replacing a pending handshake must not free the client's IP";
    ASSERT_EQ(toClient(*c, reply_, reply_len_), Client::Event::kEstablished);
    ASSERT_EQ(toServer(cout_, cout_len_), Server::Rx::kConsumed);
    EXPECT_EQ(c->tunIp(), 0x0A080002u);
}

TEST_F(V2Engine, LostAckIsCoveredByTheFirstData)
{
    auto c = makeClient(client_keys_);
    connect(*c, /*deliver_ack=*/false);
    EXPECT_EQ(server_->activeSessions(), 0u);
    ASSERT_EQ(toServer(dataFrom(*c, c->tunIp())), Server::Rx::kDeliver);
    EXPECT_EQ(server_->stats().hs_confirm_data, 1u);
    EXPECT_EQ(server_->stats().hs_confirm_ack, 0u);
    EXPECT_EQ(server_->activeSessions(), 1u);
}

TEST_F(V2Engine, KeepaliveAlsoConfirms)
{
    auto c = makeClient(client_keys_);
    connect(*c, false);
    uint8_t b[64];
    ASSERT_EQ(toServer(b, c->sealKeepalive(now_, b)), Server::Rx::kConsumed);
    EXPECT_EQ(server_->stats().hs_confirm_data, 1u);
}

TEST_F(V2Engine, PendingHandshakeExpiresAndFreesTheAddress)
{
    auto c = makeClient(client_keys_);
    ASSERT_EQ(toServer(init(*c)), Server::Rx::kReply);
    std::vector<Server::Outgoing> out;
    now_ += 9 * kSec;
    server_->tick(now_, out);
    EXPECT_EQ(server_->pendingSessions(), 1u);
    now_ += 1 * kSec;
    server_->tick(now_, out);
    EXPECT_EQ(server_->pendingSessions(), 0u);
    EXPECT_EQ(pool_.releases, 1);
    EXPECT_EQ(pool_.freeCount(), 10u);
}

TEST_F(V2Engine, ReplayedAndTamperedTransportIsDropped)
{
    auto c = makeClient(client_keys_);
    connect(*c);
    const auto d = dataFrom(*c, c->tunIp());
    auto forged = d;
    forged[20] ^= 1;
    EXPECT_EQ(toServer(forged), Server::Rx::kDropped);
    EXPECT_EQ(server_->stats().tr_drop_auth, 1u);
    EXPECT_EQ(toServer(d), Server::Rx::kDeliver) << "a forged packet must not consume its counter";
    EXPECT_EQ(toServer(d), Server::Rx::kDropped);
    EXPECT_EQ(server_->stats().tr_drop_replay, 1u);

    auto unknown = d;
    putU32(unknown.data() + 2, 0xdeadbeef);
    EXPECT_EQ(toServer(unknown), Server::Rx::kDropped);
    EXPECT_EQ(server_->stats().tr_drop_no_session, 1u);

    auto header_changed = dataFrom(*c, c->tunIp());
    header_changed[1] = kKeepalive; // type is AAD (D4)
    EXPECT_EQ(toServer(header_changed), Server::Rx::kDropped);
    EXPECT_EQ(server_->stats().tr_drop_auth, 2u);
}

TEST_F(V2Engine, InnerSourceAddressMustBeTheClientsOwn)
{
    auto c = makeClient(client_keys_);
    connect(*c);
    EXPECT_EQ(toServer(dataFrom(*c, 0x0A080003u)), Server::Rx::kDropped); // another client's IP
    EXPECT_EQ(server_->stats().tr_drop_src_ip, 1u);
    uint8_t b[64];
    const uint8_t junk[10] = {0x45};
    EXPECT_EQ(toServer(b, c->sealData(junk, sizeof(junk), now_, b)), Server::Rx::kDropped); // < 20 B
    EXPECT_EQ(server_->stats().tr_drop_src_ip, 2u);
}

TEST_F(V2Engine, RoamingFollowsOnlyAuthenticatedPackets)
{
    auto c = makeClient(client_keys_);
    connect(*c);
    const Endpoint moved{0x09090909, 6000};
    auto forged = dataFrom(*c, c->tunIp());
    forged.back() ^= 1;
    EXPECT_EQ(toServer(forged, moved), Server::Rx::kDropped);
    uint8_t wire[256];
    size_t n;
    Endpoint to;
    const auto ip = ipPacket(1, c->tunIp());
    ASSERT_TRUE(server_->seal(c->tunIp(), ip.data(), ip.size(), now_, wire, n, to));
    EXPECT_EQ(to, (Endpoint{0x01020304, 4000})) << "forged packet moved the endpoint";

    ASSERT_EQ(toServer(dataFrom(*c, c->tunIp()), moved), Server::Rx::kDeliver);
    ASSERT_TRUE(server_->seal(c->tunIp(), ip.data(), ip.size(), now_, wire, n, to));
    EXPECT_EQ(to, moved);
    EXPECT_EQ(server_->stats().roams, 1u);
}

TEST_F(V2Engine, RekeyKeepsTheAddressAndOldKeyStillDecrypts)
{
    auto c = makeClient(client_keys_);
    connect(*c);
    const std::string first_id = c->handshakeId();
    const auto in_flight = dataFrom(*c, c->tunIp()); // sealed with the old key

    now_ += 120 * kSec; // rekey after 120 s (client-initiated)
    connect(*c);
    EXPECT_NE(c->handshakeId(), first_id);
    EXPECT_EQ(c->tunIp(), 0x0A080002u);
    EXPECT_EQ(server_->stats().rekeys, 1u);
    EXPECT_EQ(server_->activeSessions(), 2u); // current + previous
    EXPECT_EQ(pool_.allocations, 1);

    EXPECT_EQ(toServer(in_flight), Server::Rx::kDeliver) << "late packet under the previous key";
    // Server now sends with the new key; the client decrypts it
    uint8_t wire[256];
    size_t n;
    Endpoint to;
    const auto ip = ipPacket(0x08080808u, c->tunIp());
    ASSERT_TRUE(server_->seal(c->tunIp(), ip.data(), ip.size(), now_, wire, n, to));
    EXPECT_EQ(toClient(*c, wire, n), Client::Event::kData);

    // The previous session ages out at reject-after; the current one stays
    std::vector<Server::Outgoing> out;
    now_ += 61 * kSec;
    ASSERT_EQ(toServer(dataFrom(*c, c->tunIp())), Server::Rx::kDeliver);
    server_->tick(now_, out);
    EXPECT_EQ(server_->activeSessions(), 1u);
    EXPECT_EQ(server_->stats().removed_reject, 1u);
}

TEST_F(V2Engine, ByeRemovesEverythingAndFreesTheAddress)
{
    auto c = makeClient(client_keys_);
    connect(*c);
    uint8_t b[64];
    ASSERT_EQ(toServer(b, c->sealBye(now_, b)), Server::Rx::kConsumed);
    EXPECT_EQ(server_->activeSessions(), 0u);
    EXPECT_EQ(server_->stats().removed_bye, 1u);
    EXPECT_EQ(pool_.releases, 1);
    EXPECT_FALSE(server_->ownsTunIp(0x0A080002u));
}

TEST_F(V2Engine, KeepalivesAndIdleRemoval)
{
    auto c = makeClient(client_keys_);
    connect(*c);
    std::vector<Server::Outgoing> out;
    now_ += 14 * kSec;
    server_->tick(now_, out);
    EXPECT_TRUE(out.empty());
    now_ += 1 * kSec;
    server_->tick(now_, out);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].pkt.size(), kTransportMinLen);
    EXPECT_EQ(toClient(*c, out[0].pkt.data(), out[0].pkt.size()), Client::Event::kKeepalive);

    out.clear();
    now_ += 180 * kSec; // nothing authenticated received for 180 s
    server_->tick(now_, out);
    EXPECT_EQ(server_->activeSessions(), 0u);
    EXPECT_EQ(server_->stats().removed_reject + server_->stats().removed_idle, 1u);
    EXPECT_EQ(pool_.releases, 1);
}

TEST_F(V2Engine, OpenModeAcceptsAnyClient)
{
    ServerConfig cfg;
    cfg.auth = ServerConfig::kOpen;
    makeServer(cfg, false);
    Keys anyone;
    auto c = makeClient(anyone);
    connect(*c);
    EXPECT_EQ(server_->activeSessions(), 1u);
}

TEST_F(V2Engine, CipherNegotiationUsesServerPreference)
{
    ServerConfig cfg;
    cfg.algorithms = {crypto::kCipherAes256Gcm, crypto::kCipherChaCha20Poly1305};
    makeServer(cfg);
    auto c = makeClient(client_keys_, {crypto::kCipherChaCha20Poly1305, crypto::kCipherAes256Gcm});
    connect(*c);
    const bool have_aes = crypto::CipherRegistry::instance().find(crypto::kCipherAes256Gcm) != nullptr;
    EXPECT_EQ(c->cipherId(), have_aes ? crypto::kCipherAes256Gcm : crypto::kCipherChaCha20Poly1305);
    ASSERT_EQ(toServer(dataFrom(*c, c->tunIp())), Server::Rx::kDeliver);
}

TEST_F(V2Engine, ClientRejectsResponsesNotForItsHandshake)
{
    auto c = makeClient(client_keys_);
    ASSERT_EQ(toServer(init(*c)), Server::Rx::kReply);
    std::vector<uint8_t> resp(reply_, reply_ + reply_len_);
    auto bad = resp;
    bad[30] ^= 1;
    EXPECT_EQ(toClient(*c, bad.data(), bad.size()), Client::Event::kNone);
    bad = resp;
    putU32(bad.data() + 6, 12345); // receiver_idx of another handshake
    EXPECT_EQ(toClient(*c, bad.data(), bad.size()), Client::Event::kNone);
    EXPECT_EQ(c->stats().resp_drop, 2u);
    EXPECT_EQ(toClient(*c, resp.data(), resp.size()), Client::Event::kEstablished);
    EXPECT_EQ(toClient(*c, resp.data(), resp.size()), Client::Event::kNone) << "no pending handshake";
}

TEST_F(V2Engine, KeylogLineOnConfirmation)
{
    std::vector<std::string> lines;
    server_->keylog = [&](const std::string &l) { lines.push_back(l); };
    auto c = makeClient(client_keys_);
    connect(*c);
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_EQ(lines[0].rfind(c->handshakeId() + " ", 0), 0u);
    EXPECT_EQ(std::count(lines[0].begin(), lines[0].end(), ' '), 3); // hsid idx k_c2s k_s2c
}
