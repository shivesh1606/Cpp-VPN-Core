// ClientManager: IP pool lifecycle, client registration with SessionLocks, lookups, roaming, sweep.
#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <cstring>

#include "crypto/backends/XorBackend.h"
#include "sessions/client/Client_Manager.h"

using namespace crypto;

namespace
{

constexpr uint32_t kBase = 0x0A080002; // 10.8.0.2

sockaddr_in addr(const char *ip, uint16_t port)
{
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}

std::unique_ptr<SessionLock> xorLock(uint8_t k)
{
    uint8_t key[kKeyBytes];
    expandV1XorKey(k, key);
    return XorBackend().newLock(key);
}

class ClientManagerTest : public testing::Test
{
protected:
    ClientManager cm{4, "10.8.0.2"};

    Client *add(uint32_t ip, const sockaddr_in &a, uint32_t sid, uint8_t k = 0x5a)
    {
        return cm.addClient(a, ip, xorLock(k), xorLock(k), sid);
    }
};

} // namespace

TEST_F(ClientManagerTest, PoolAllocatesSequentiallyAndExhausts)
{
    EXPECT_EQ(cm.getNextAvailableIp(), kBase);
    EXPECT_EQ(cm.getNextAvailableIp(), kBase + 1);
    EXPECT_EQ(cm.getNextAvailableIp(), kBase + 2);
    EXPECT_EQ(cm.getNextAvailableIp(), kBase + 3);
    EXPECT_EQ(cm.getNextAvailableIp(), 0u) << "pool of 4 is exhausted";
}

TEST_F(ClientManagerTest, FreedReservationIsReused)
{
    uint32_t ip = cm.getNextAvailableIp();
    EXPECT_TRUE(cm.isIpInUse(ip));
    cm.freeIp(ip);
    EXPECT_FALSE(cm.isIpInUse(ip));
    EXPECT_EQ(cm.getNextAvailableIp(), ip);
}

TEST_F(ClientManagerTest, AddClientRegistersAllLookupsAndOwnsLocks)
{
    uint32_t ip = cm.getNextAvailableIp();
    auto a = addr("203.0.113.7", 40000);
    Client *c = add(ip, a, 1000, 0x21);
    ASSERT_NE(c, nullptr);

    EXPECT_TRUE(cm.isIpInStateActive(ip));
    EXPECT_EQ(cm.getClientByServerIp(ip), c);
    EXPECT_EQ(cm.getClientByUdp(a), c);
    EXPECT_EQ(cm.getClientBySessionId(1000), c);
    ASSERT_NE(c->rx, nullptr);
    ASSERT_NE(c->tx, nullptr);
    EXPECT_EQ(c->tx_counter, 0u);

    // The stored locks are usable and keyed correctly
    uint8_t in[3] = {1, 2, 3}, out[3];
    c->tx->seal(0, nullptr, 0, in, 3, out);
    EXPECT_EQ(out[0], 1 ^ 0x21);
}

TEST_F(ClientManagerTest, AddClientRejectsMissingLocks)
{
    uint32_t ip = cm.getNextAvailableIp();
    auto a = addr("203.0.113.7", 40000);
    EXPECT_EQ(cm.addClient(a, ip, nullptr, xorLock(1), 1000), nullptr);
    EXPECT_EQ(cm.addClient(a, ip, xorLock(1), nullptr, 1000), nullptr);
    EXPECT_FALSE(cm.isIpInStateActive(ip));
    EXPECT_EQ(cm.getClientByUdp(a), nullptr);
}

TEST_F(ClientManagerTest, AddClientRejectsActiveIpAndOutOfPoolIp)
{
    uint32_t ip = cm.getNextAvailableIp();
    ASSERT_NE(add(ip, addr("203.0.113.7", 1), 1000), nullptr);
    EXPECT_EQ(add(ip, addr("203.0.113.8", 2), 1001), nullptr) << "IP already active";
    EXPECT_EQ(add(kBase + 100, addr("203.0.113.9", 3), 1002), nullptr) << "outside pool";
}

TEST_F(ClientManagerTest, RemoveBySessionIdFreesEverything)
{
    uint32_t ip = cm.getNextAvailableIp();
    auto a = addr("198.51.100.1", 5555);
    ASSERT_NE(add(ip, a, 1000), nullptr);

    cm.removeClientBySessionId(1000);
    EXPECT_FALSE(cm.isIpInUse(ip));
    EXPECT_EQ(cm.getClientByServerIp(ip), nullptr);
    EXPECT_EQ(cm.getClientByUdp(a), nullptr);
    EXPECT_EQ(cm.getClientBySessionId(1000), nullptr);
}

TEST_F(ClientManagerTest, RoamingMovesUdpMapping)
{
    uint32_t ip = cm.getNextAvailableIp();
    auto wifi = addr("198.51.100.1", 1111);
    auto lte = addr("192.0.2.50", 2222);
    Client *c = add(ip, wifi, 1000);
    ASSERT_NE(c, nullptr);

    cm.updateClientEndpoint(1000, lte);
    EXPECT_EQ(cm.getClientByUdp(lte), c);
    EXPECT_EQ(cm.getClientByUdp(wifi), nullptr);
    EXPECT_EQ(c->client_udp_addr.sin_port, htons(2222));
}

TEST_F(ClientManagerTest, SweepRemovesOnlySilentClients)
{
    uint32_t ip1 = cm.getNextAvailableIp(), ip2 = cm.getNextAvailableIp();
    Client *old_c = add(ip1, addr("198.51.100.1", 1), 1000);
    Client *new_c = add(ip2, addr("198.51.100.2", 2), 1001);
    ASSERT_NE(old_c, nullptr);
    ASSERT_NE(new_c, nullptr);
    old_c->last_seen = time(nullptr) - 120;

    EXPECT_EQ(cm.sweepDeadClients(60), 1);
    EXPECT_EQ(cm.getClientBySessionId(1000), nullptr);
    EXPECT_NE(cm.getClientBySessionId(1001), nullptr);
    EXPECT_FALSE(cm.isIpInUse(ip1));
}

TEST_F(ClientManagerTest, TouchUpdatesLastSeen)
{
    uint32_t ip = cm.getNextAvailableIp();
    Client *c = add(ip, addr("198.51.100.1", 1), 1000);
    ASSERT_NE(c, nullptr);
    c->last_seen = 0;
    cm.touchClient(1000);
    EXPECT_GT(c->last_seen, 0);
}

// Known protocol v1 defect (plan item H3, fixed by M4's receiver_idx indexing):
// a client restarting from the same ip:port gets a second session; when the stale one is swept,
// freeIp() erases the ip:port mapping that now belongs to the NEW session. v1 self-heals on the
// next DATA packet via the session-id roaming fallback. Enable this test in M4.
TEST_F(ClientManagerTest, DISABLED_SweepOfStaleSessionKeepsNewSessionMapping)
{
    auto a = addr("198.51.100.1", 4000);
    uint32_t ip1 = cm.getNextAvailableIp(), ip2 = cm.getNextAvailableIp();
    Client *stale = add(ip1, a, 1000);
    Client *fresh = add(ip2, a, 1001); // same ip:port after app restart
    ASSERT_NE(stale, nullptr);
    ASSERT_NE(fresh, nullptr);
    stale->last_seen = time(nullptr) - 120;

    cm.sweepDeadClients(60);
    EXPECT_EQ(cm.getClientByUdp(a), fresh);
}
