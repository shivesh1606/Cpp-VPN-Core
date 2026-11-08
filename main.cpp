// server.cpp -- Minimal UDP <-> TUN forwarder (for testing only)

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <algorithm> // for std::max
#include "sessions/client/Client_Manager.h"
#include "crypto/DiffieHellman.h"
#include "net/tun/TunDevice.h"
#include "net/ip/Ipv4.h"
#include "net/ip/Cidr.h"
#include "config/Cli.h"
#include "config/NodeConfig.h"
#include "crypto/NodeIdentity.h"
#include "protocol/v2/Server.h"
#include <memory>
#include <time.h>
#include "version.h"
#include <cstdio>
#include <sstream>
#include "crypto/CipherRegistry.h"
#include "crypto/backends/XorBackend.h"
#include "sessions/session/ClientSession.h"
#include "protocol/Handshake.h"
#include "net/socket/SocketManager.h"
#include <sys/uio.h>
#include <sys/time.h>
#include "utils/counter_definition.h"
#include "utils/logger.h"
#include <signal.h>
#include "utils/profiling.h"

static volatile sig_atomic_t g_shutdown = 0;

void handle_sigint(int)
{
    std::cout << "[INFO] Caught termination signal, shutting down...\n";
    g_shutdown = 1;
}

constexpr int RX_BATCH = 8;
constexpr int RX_BUF_SIZE = 2000;
constexpr int TX_BATCH = 3;
constexpr int TX_BUF_SIZE = 2000;

void handleUdpToTun(ClientManager &cm, int &tun,
                    unsigned char *buf, int &n,
                    struct sockaddr_in &client_addr, uint32_t  session_id)

{
    static uint8_t temp[2000];
    Client *client;
    PROFILE_SCOPE_START(lookup_t0);
    client = cm.getClientByUdp(client_addr);
    PROFILE_SCOPE_END(lookup_t0, global_stats.lookup_cycles);
    if (!client)
    {
        session_id = ntohl(session_id);
        LOG(LOG_INFO, "Session ID in packet: %u", session_id);
        // 1. Try Roaming: Lookup by the Session ID inside the packet
        client = cm.getClientBySessionId(session_id);

        if (client)
        {
            // 2. Found them! Update the port/IP for future packets
            cm.updateClientEndpoint(session_id, client_addr);
        }
        else
        {
            LOG(LOG_WARN, "Unauthorized packet from %s", inet_ntoa(client_addr.sin_addr));
            return;
        }
    }
    // Touch last_seen so the client doesn't get swept
    client->last_seen = time(nullptr);

    // Encrypted payload (ciphertext + tag) starts AFTER header
    const size_t enc_len = n - sizeof(PacketHeader);
    const uint8_t *enc_payload = buf + sizeof(PacketHeader);
    const size_t overhead = client->rx->overhead();
    // Basic sanity: the plaintext must hold at least an IPv4 header (checked before decrypting)
    if (enc_len < net::kIpv4MinHeader + overhead)
    {
        LOG(LOG_WARN, "Encrypted packet too small (%zu bytes) - skipping", enc_len);
        STAT_ADD(global_stats.udp_rx_drops, 1);
        return;
    }
    // Decrypt payload. v1 has no counter or AAD; v2 passes the header as AAD (design 01 C1/C2)
    PROFILE_SCOPE_START(dec_t0);
    bool ok = client->rx->open(0, nullptr, 0, enc_payload, enc_len, temp);
    PROFILE_SCOPE_END(dec_t0, global_stats.dec_cycles);
    if (!ok)
    {
        STAT_ADD(global_stats.rx_auth_fail, 1);
        return;
    }
    const size_t plain_len = enc_len - overhead;
    PROFILE_SCOPE_START(tun_wr_t0);
    ssize_t write_count = write(tun, temp, plain_len);
    PROFILE_SCOPE_END(tun_wr_t0, global_stats.tun_write_cycles);

    if (write_count < 0)
    {
        perror("write tun");
        LOG(LOG_ERROR, "Failed to write to TUN");
        STAT_ADD(global_stats.tun_rx_drops, 1);
        return;
    }
    STAT_ADD(global_stats.tun_tx_pkts, 1);
    STAT_ADD(global_stats.tun_tx_bytes, write_count);
}

void handleHandshake(PacketHeader *hdr, int &n, unsigned char *buf,
                     struct sockaddr_in &client_addr,
                     int &sock,
                     ClientSession &client_connection_sessions,
                     ClientManager &cm)
{
    // Placeholder for handshake handling logic
    if (hdr->type == PKT_HELLO)
    {
        if (n < (int)sizeof(HelloPacket))
        {
            LOG(LOG_WARN, "Short HelloPacket packet");
            return;
        }

        HelloPacket *hello = (HelloPacket *)buf;

        SessionState *pending = client_connection_sessions.getSession(client_addr);
        if (pending != nullptr)
        {
            if (pending->client_magic == hello->client_magic)
            {
                // Retransmitted HELLO (our WELCOME was lost or late): resend the SAME
                // WELCOME so the client's key/IP always match what ACK will register
                WelcomePacket welcome{};
                welcome.hdr.type = PKT_WELCOME;
                welcome.hdr.session_id = htonl(pending->session_id);
                welcome.assigned_tun_ip = htonl(pending->assigned_tun_ip);
                welcome.ys = htonl(modexp(G, pending->b, P));
                pending->created_at = time(nullptr); // client is still trying, keep it alive

                sendto(sock, (char *)&welcome, sizeof(welcome), 0,
                       (struct sockaddr *)&client_addr, sizeof(client_addr));
                LOG(LOG_INFO, "Handshake: duplicate HELLO from %s, resent WELCOME for session %u",
                    inet_ntoa(client_addr.sin_addr), pending->session_id);
                return;
            }

            // New handshake from the same address: drop the stale one and release its IP
            LOG(LOG_INFO, "Handshake: new HELLO from %s replaces pending session %u",
                inet_ntoa(client_addr.sin_addr), pending->session_id);
            cm.freeIp(pending->assigned_tun_ip);
            client_connection_sessions.eraseSession(client_addr);
        }

        uint32_t nextAvailableIp = cm.getNextAvailableIp();
        uint32_t session_id=cm.generateSessionId();
        if (nextAvailableIp == 0)
        {
            LOG(LOG_ERROR, "No available IPs to assign to new client");
            return;
        }

        uint32_t assigned_ip = nextAvailableIp;

        WelcomePacket welcome{};
        welcome.hdr.type = PKT_WELCOME;
        welcome.hdr.session_id = htonl(session_id); // Add this!;
        welcome.assigned_tun_ip = htonl(assigned_ip);
        long long random_b = randomNumGen(1000, 5000);
        welcome.ys = htonl(modexp(G, random_b, P)); // server's public value
        // Create SessionState for this client
        client_connection_sessions.addSession(
            client_addr,
            hello->client_magic,
            assigned_ip,
            ntohl(hello->yc),
            random_b,session_id);

        sendto(sock,
               (char *)&welcome,
               sizeof(welcome),
               0,
               (struct sockaddr *)&client_addr,
               sizeof(client_addr));
        char client_ip_str[INET_ADDRSTRLEN];
        char assigned_ip_str[INET_ADDRSTRLEN];

        // Use inet_ntop to avoid the static buffer overlap bug of inet_ntoa
        struct in_addr net_addr;
        net_addr.s_addr = welcome.assigned_tun_ip;

        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &net_addr, assigned_ip_str, INET_ADDRSTRLEN);

        LOG(LOG_INFO, "Handshake: Client %s -> Assigned Virtual IP %s , Session ID %u",
            client_ip_str,
            assigned_ip_str, session_id);
    }
    else if (hdr->type == PKT_CLIENT_ACK)
    {
        if (n < (int)sizeof(ClientAckPacket))
        {
            LOG(LOG_WARN, "Short ClientAckPacket packet");
            STAT_ADD(global_stats.handshake_failures, 1);
            return;
        }

        // check if session exists, etc.
        SessionState *session = client_connection_sessions.getSession(client_addr);
        if (session == nullptr)
        {
            LOG(LOG_WARN, "No session found for Client ACK from %s",
                inet_ntoa(client_addr.sin_addr));
            STAT_ADD(global_stats.handshake_failures, 1);
            return;
        }
        uint32_t shared_secret = modexp(session->yc, session->b, P);
        uint8_t xor_key = calculateXORKey(shared_secret);

        // Protocol v1: one XOR byte, same key both directions (design 01, section 1)
        const crypto::CipherBackend *xor_backend = crypto::CipherRegistry::instance().find(crypto::kCipherXor);
        uint8_t key[crypto::kKeyBytes];
        crypto::expandV1XorKey(xor_key, key);

        // Add client to ClientManager
        if (!cm.addClient(client_addr, session->assigned_tun_ip,
                          xor_backend->newLock(key), xor_backend->newLock(key),
                          session->session_id))
        {
            LOG(LOG_ERROR, "Handshake: failed to register session %u", session->session_id);
            STAT_ADD(global_stats.handshake_failures, 1);
        }
        // Delete session state as handshake is complete
        client_connection_sessions.eraseSession(client_addr);
    }

    else if (hdr->type == PKT_BYE)
    {
        if (n < (int)sizeof(PacketHeader))
        {
            LOG(LOG_WARN, "Short BYE packet");
            return;
        }

        uint32_t session_id = ntohl(hdr->session_id);
        LOG(LOG_INFO, "[BYE] Received disconnect from %s for session %u",
            inet_ntoa(client_addr.sin_addr), session_id);

        cm.removeClientBySessionId(session_id);
    }
    else if (hdr->type == PKT_KEEPALIVE)
    {
        if (n < (int)sizeof(PacketHeader))
            return;

        uint32_t session_id = ntohl(hdr->session_id);
        cm.touchClient(session_id);
        // No response needed — just updates last_seen
    }
    else
    {
        LOG(LOG_WARN, "Unknown packet type: %d", hdr->type);
        STAT_ADD(global_stats.handshake_failures, 1);
        return;
    }
}
// Protocol v2 uses the same client address pool as v1 (one tun0).
class ClientManagerPool : public v2::IpPool
{
public:
    explicit ClientManagerPool(ClientManager &cm) : cm_(cm) {}
    uint32_t allocate() override { return cm_.getNextAvailableIp(); }
    void activate(uint32_t ip) override { cm_.makeIpInUse(ip); }
    void release(uint32_t ip) override { cm_.freeIp(ip); }

private:
    ClientManager &cm_;
};

static uint64_t monotonicMs()
{
    timespec t{};
    clock_gettime(CLOCK_MONOTONIC, &t);
    return uint64_t(t.tv_sec) * 1000 + uint64_t(t.tv_nsec) / 1000000;
}

// Builds the v2 responder from node.conf (design 02 section 7). Returns null when the node has
// no identity (no config file): then only protocol v1 is served, as before M3.
static std::unique_ptr<v2::Server> makeV2Server(const config::NodeConfig &cfg,
                                                const crypto::NodeIdentity &id, v2::IpPool &pool)
{
    if (!id.loaded())
        return nullptr;
    v2::ServerConfig sc;
    sc.auth = cfg.auth_mode == "open" ? v2::ServerConfig::kOpen : v2::ServerConfig::kAllowlist;
    sc.allowed.insert(cfg.allowed_keys.begin(), cfg.allowed_keys.end());
    auto idOf = [](const std::string &name) -> int {
        for (const auto &b : crypto::CipherRegistry::instance().all())
            if (name == b->algorithmName())
                return b->algorithmId();
        return -1;
    };
    sc.algorithms.clear();
    for (const auto &a : cfg.algorithms)
        if (idOf(a) >= 0)
            sc.algorithms.push_back(uint8_t(idOf(a)));
    for (const auto &kv : cfg.impl)
        if (idOf(kv.first) >= 0)
            sc.impl[uint8_t(idOf(kv.first))] = kv.second;
    sc.allow_insecure_xor = cfg.allow_insecure_xor;
    sc.keepalive_s = uint16_t(cfg.keepalive_s);
    sc.pending_expiry_ms = uint32_t(cfg.pending_expiry_s) * 1000;
    sc.reject_after_ms = uint32_t(cfg.reject_after_s) * 1000;
    auto server = std::make_unique<v2::Server>(id.privateKey(), sc, pool);
#if CPPVPN_ENABLE_KEYLOG
    if (const char *path = getenv("VPN_KEYLOG_FILE"))
    {
        FILE *f = std::fopen(path, "a");
        if (f)
        {
            LOG(LOG_WARN, "KEYLOG ENABLED: session keys are written to %s (debug build)", path);
            server->keylog = [f](const std::string &line) {
                std::fprintf(f, "%s\n", line.c_str());
                std::fflush(f);
            };
        }
    }
#endif
    LOG(LOG_INFO, "Protocol v2 enabled: auth=%s (%zu allowed clients), v1 %s",
        cfg.auth_mode.c_str(), cfg.allowed_keys.size(), cfg.accept_v1 ? "also accepted" : "disabled");
    return server;
}

static void logV2Stats(const v2::Server &s)
{
    const v2::ServerStats &v = s.stats();
    LOG(LOG_INFO,
        "v2: active %zu pending %zu | hs resp %lu retx %lu confirm ack/data %lu/%lu rekeys %lu expired %lu | "
        "hs drop fmt %lu mac1 %lu decrypt %lu auth %lu replay %lu no_cipher %lu pool %lu | "
        "tr drop fmt %lu no_session %lu replay %lu auth %lu src_ip %lu ack %lu | roams %lu | "
        "removed bye/reject/idle %lu/%lu/%lu",
        s.activeSessions(), s.pendingSessions(), v.hs_resp_sent, v.hs_retransmit, v.hs_confirm_ack,
        v.hs_confirm_data, v.rekeys, v.hs_expired, v.hs_drop_format, v.hs_drop_mac1, v.hs_drop_decrypt,
        v.hs_drop_auth, v.hs_drop_replay, v.hs_drop_no_cipher, v.hs_drop_pool_empty, v.tr_drop_format,
        v.tr_drop_no_session, v.tr_drop_replay, v.tr_drop_auth, v.tr_drop_src_ip, v.tr_drop_ack, v.roams,
        v.removed_bye, v.removed_reject, v.removed_idle);
}

// --gen-key / --pubkey / --check-config / --help / --version. Returns the exit code, or -1 to
// continue into server mode. These modes need no root and touch neither TUN nor the network.
static int runCliMode(const config::CliOptions &cli, const config::NodeConfig &cfg,
                      const config::ConfigReport &report)
{
    switch (cli.mode)
    {
    case config::CliOptions::kHelp:
        std::fputs(config::usageText(), stdout);
        return 0;
    case config::CliOptions::kVersion:
        std::printf("vpn_server %d.%d (build %d)\n", PROJECT_VERSION_MAJOR, PROJECT_VERSION_MINOR,
                    PROJECT_BUILD_NUMBER);
        return 0;
    case config::CliOptions::kGenKey:
    {
        crypto::NodeIdentity id;
        std::string err;
        if (!crypto::generateNodeKey(cli.key_path, cli.force, id, err))
        {
            std::fprintf(stderr, "error: %s\n", err.c_str());
            return 1;
        }
        std::fprintf(stderr, "wrote %s (mode 0600). Public key (S_pub):\n", cli.key_path.c_str());
        std::printf("%s\n", id.publicKeyBase64Url().c_str());
        return 0;
    }
    case config::CliOptions::kPubKey:
    {
        crypto::NodeIdentity id;
        std::string err;
        if (!crypto::loadNodeKey(cli.key_path, id, err))
        {
            std::fprintf(stderr, "error: %s\n", err.c_str());
            return 1;
        }
        std::printf("%s\n", id.publicKeyBase64Url().c_str());
        return 0;
    }
    case config::CliOptions::kCheckConfig:
    {
        for (const auto &w : report.warnings)
            std::fprintf(stderr, "warning: %s\n", w.c_str());
        for (const auto &e : report.errors)
            std::fprintf(stderr, "error: %s\n", e.c_str());
        if (!report.ok())
            return 2;
        std::fputs(config::describe(cfg).c_str(), stdout);
        if (!cfg.node_key.empty())
        {
            crypto::NodeIdentity id;
            std::string err;
            if (!crypto::loadNodeKey(cfg.node_key, id, err))
            {
                std::fprintf(stderr, "error: %s\n", err.c_str());
                return 2;
            }
            std::printf("node public key   %s\n", id.publicKeyBase64Url().c_str());
        }
        std::printf("config OK\n");
        return 0;
    }
    case config::CliOptions::kRun:
        break;
    }
    return -1;
}

int main(int argc, char **argv)
{
    // ---- command line and configuration (plan M3) ----
    config::CliOptions cli;
    std::string cli_error;
    if (!config::parseCli(argc, argv, cli, cli_error))
    {
        std::fprintf(stderr, "error: %s\n\n%s", cli_error.c_str(), config::usageText());
        return 2;
    }
    std::string config_path = cli.config_path;
    if (!cli.config_given && access(config::kDefaultConfigPath, F_OK) == 0)
        config_path = config::kDefaultConfigPath; // default location (N3), only if present
    config::ConfigReport report;
    const config::NodeConfig cfg = (cli.mode == config::CliOptions::kRun ||
                                    cli.mode == config::CliOptions::kCheckConfig)
                                       ? config::loadNodeConfig(config_path, cli.overrides, report)
                                       : config::NodeConfig{};
    const int cli_rc = runCliMode(cli, cfg, report);
    if (cli_rc >= 0)
        return cli_rc;

    log_init();
    for (const auto &w : report.warnings)
        LOG(LOG_WARN, "config: %s", w.c_str());
    if (!report.ok())
    {
        for (const auto &e : report.errors)
        {
            LOG(LOG_ERROR, "config: %s", e.c_str());
            std::fprintf(stderr, "error: %s\n", e.c_str());
        }
        log_flush();
        return 2;
    }
    {
        std::istringstream lines(config::describe(cfg));
        for (std::string line; std::getline(lines, line);)
            LOG(LOG_INFO, "config: %s", line.c_str());
    }

    // Node identity (N1): required whenever a config file is used; v1 does not use it yet.
    crypto::NodeIdentity node_identity;
    if (!cfg.node_key.empty())
    {
        std::string err;
        if (!crypto::loadNodeKey(cfg.node_key, node_identity, err))
        {
            LOG(LOG_ERROR, "node identity: %s", err.c_str());
            std::fprintf(stderr, "error: %s\n", err.c_str());
            log_flush();
            return 2;
        }
        LOG(LOG_INFO, "Node public key (S_pub): %s", node_identity.publicKeyBase64Url().c_str());
    }
    else
        LOG(LOG_WARN, "No node identity (no config file): protocol v1 only. "
                      "Create one with --gen-key before protocol v2 (M4).");

    struct sigaction sa{};
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // IMPORTANT: no SA_RESTART
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    ClientSession client_connection_sessions;
    ClientManager cm(static_cast<int>(cfg.pool_size), net::ipv4ToString(cfg.pool_start).c_str());
    int tun = TunDevice::create(cfg.tun_name.c_str());
    if (cfg.configure_tun)
    {
        std::string err;
        if (!TunDevice::configure(cfg.tun_name.c_str(), cfg.tun_addr, cfg.tun_prefix, cfg.mtu, err))
        {
            LOG(LOG_ERROR, "TUN configuration failed: %s", err.c_str());
            std::fprintf(stderr, "error: TUN configuration failed: %s\n", err.c_str());
            log_flush();
            return 1;
        }
    }
    if (!crypto::CipherRegistry::instance().find(crypto::kCipherXor))
    {
        LOG(LOG_ERROR, "Protocol v1 requires the xor backend, which is not registered");
        return 1;
    }
    for (const auto &b : crypto::CipherRegistry::instance().all())
        LOG(LOG_INFO, "Cipher backend: id %u %s/%s%s", b->algorithmId(), b->algorithmName(),
            b->implName(), b->insecure() ? " (INSECURE, protocol v1 only)" : "");
    ClientManagerPool v2_pool(cm);
    std::unique_ptr<v2::Server> v2srv = makeV2Server(cfg, node_identity, v2_pool);
    if (!cfg.accept_v1 && !v2srv)
    {
        LOG(LOG_ERROR, "node.accept_v1 = false needs protocol v2 (a node key)");
        log_flush();
        return 2;
    }
    int sock = SocketManager::createUdpSocket(cfg.port);
    if (sock < 0)
    {
        std::cerr << "[ERROR] Failed to create UDP socket\n";
        return 1;
    }
    unsigned char main_loop_buf[2000];
    const int HANDSHAKE_TIMEOUT = cfg.pending_expiry_s; // [timers] pending_expiry_s (default 10)
    const int CLIENT_DEAD_TIMEOUT = cfg.dead_after_s;   // [timers] dead_after_s (default 60): sweep idle clients
    fcntl(sock, F_SETFL, O_NONBLOCK);
    fcntl(tun, F_SETFL, O_NONBLOCK);

    LOG(LOG_INFO, "Server started, socket fd %d, TUN fd %d", sock, tun);

    // Per-batch storage (stack-owned, safe)
    struct mmsghdr rx_msgs[RX_BATCH];
    struct iovec rx_iovecs[RX_BATCH];
    struct sockaddr_in rx_addrs[RX_BATCH];
    unsigned char rx_bufs[RX_BATCH][RX_BUF_SIZE];
    memset(rx_msgs, 0, sizeof(rx_msgs));
    memset(rx_addrs, 0, sizeof(rx_addrs));
    for (int i = 0; i < RX_BATCH; i++)
    {
        rx_iovecs[i].iov_base = rx_bufs[i];
        rx_iovecs[i].iov_len = RX_BUF_SIZE;

        rx_msgs[i].msg_hdr.msg_iov = &rx_iovecs[i];
        rx_msgs[i].msg_hdr.msg_iovlen = 1;
        rx_msgs[i].msg_hdr.msg_control = nullptr;
        rx_msgs[i].msg_hdr.msg_controllen = 0;

        rx_msgs[i].msg_hdr.msg_name = &rx_addrs[i];
        rx_msgs[i].msg_hdr.msg_namelen = sizeof(rx_addrs[i]);
    }

    struct mmsghdr tx_msgs[TX_BATCH];
    struct iovec tx_iovecs[TX_BATCH];
    unsigned char tx_bufs[TX_BATCH][TX_BUF_SIZE];
    struct sockaddr_in tx_addrs[TX_BATCH]; // v2 destinations (v1 points at Client::client_udp_addr)
    memset(tx_addrs, 0, sizeof(tx_addrs));
    static unsigned char v2_plain[RX_BUF_SIZE], v2_reply[v2::kRespLen];
    std::vector<v2::Server::Outgoing> v2_out;
    memset(tx_msgs, 0, sizeof(tx_msgs));
    for (int i = 0; i < TX_BATCH; i++)
    {
        tx_msgs[i].msg_hdr.msg_iov = &tx_iovecs[i];
        tx_msgs[i].msg_hdr.msg_iovlen = 1;
    }

    static time_t last = time(nullptr);
    while (!g_shutdown)
    {

        // Periodically erase expired sessions
        time_t now = time(nullptr);

        if (now != last)
        {
            last = now;

            // select() now wakes every second; skip the stats block for idle seconds
            if (global_stats.udp_rx_pkts || global_stats.tun_rx_pkts || global_stats.handshake_pkts)
            {
                global_stats.print_Stats();
                if (v2srv)
                    logV2Stats(*v2srv);
            }
            global_stats.reset_Stats();

            // Protocol v2 timers: pending expiry, reject-after, idle removal, server keepalives
            if (v2srv)
            {
                v2_out.clear();
                v2srv->tick(monotonicMs(), v2_out);
                for (const auto &o : v2_out)
                {
                    sockaddr_in to{};
                    to.sin_family = AF_INET;
                    to.sin_addr.s_addr = o.to.addr;
                    to.sin_port = o.to.port;
                    sendto(sock, o.pkt.data(), o.pkt.size(), 0, (sockaddr *)&to, sizeof(to));
                }
            }

            // Handshakes that never got an ACK: return their reserved IPs to the pool
            for (uint32_t ip : client_connection_sessions.eraseExpiredSessions(HANDSHAKE_TIMEOUT))
            {
                cm.freeIp(ip);
            }

            // Sweep clients that haven't sent data/keepalive
            int swept = cm.sweepDeadClients(CLIENT_DEAD_TIMEOUT);
            if (swept > 0)
            {
                LOG(LOG_INFO, "[SWEEP] Removed %d dead client(s)", swept);
            }
        }

        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(sock, &rf);
        FD_SET(tun, &rf);

        int nf = std::max(sock, tun) + 1;
        // Wake at least once a second so housekeeping (handshake expiry, dead-client
        // sweep, stats) runs even when no packets arrive
        struct timeval tv{1, 0};
        int ret = select(nf, &rf, nullptr, nullptr, &tv);
        if (ret < 0)
        {
            perror("select");
            continue;
        }

        if (FD_ISSET(sock, &rf))
        {

            while (true)
            {

                PROFILE_SCOPE_START(rx_syscall_t0);
                int rcvd = recvmmsg(sock, rx_msgs, RX_BATCH, 0, nullptr);
                PROFILE_SCOPE_END(rx_syscall_t0, global_stats.rx_syscall_cycles);

                if (rcvd > 0)
                {
                    STAT_ADD(global_stats.udp_rx_batches, 1);
                    PROFILE_SCOPE_START(rx_batch_t0);
                    for (int i = 0; i < rcvd; i++)
                    {

                        int n = rx_msgs[i].msg_len;
                        STAT_ADD(global_stats.udp_rx_pkts, 1);
                        unsigned char *buf = rx_bufs[i];
                        struct sockaddr_in &client_addr = rx_addrs[i];
                        // H2: datagram larger than RX_BUF_SIZE was cut by the kernel; drop it
                        if (rx_msgs[i].msg_hdr.msg_flags & MSG_TRUNC)
                        {
                            STAT_ADD(global_stats.udp_rx_drops, 1);
                            STAT_ADD(global_stats.udp_rx_truncated, 1);
                            continue;
                        }
                        // Protocol v2 packets start with 0x20, never a v1 type byte (design 02 section 3)
                        if (n >= 1 && buf[0] == v2::kVersion)
                        {
                            if (!v2srv)
                            {
                                STAT_ADD(global_stats.udp_rx_drops, 1); // no node key: v1 only
                                continue;
                            }
                            const v2::Endpoint from{client_addr.sin_addr.s_addr, client_addr.sin_port};
                            size_t reply_len = 0, plain_len = 0;
                            PROFILE_SCOPE_START(v2_rx_t0);
                            const v2::Server::Rx r = v2srv->receive(buf, (size_t)n, from, monotonicMs(),
                                                                    v2_reply, reply_len, v2_plain, plain_len);
                            PROFILE_SCOPE_END(v2_rx_t0, global_stats.dec_cycles);
                            if (r == v2::Server::Rx::kDeliver)
                            {
                                PROFILE_SCOPE_START(tun_wr_v2_t0);
                                if (write(tun, v2_plain, plain_len) < 0)
                                    STAT_ADD(global_stats.udp_rx_drops, 1);
                                PROFILE_SCOPE_END(tun_wr_v2_t0, global_stats.tun_write_cycles);
                                STAT_ADD(global_stats.udp_rx_bytes, n);
                            }
                            else if (r == v2::Server::Rx::kReply)
                            {
                                sendto(sock, v2_reply, reply_len, 0, (sockaddr *)&client_addr, sizeof(client_addr));
                                STAT_ADD(global_stats.handshake_pkts, 1);
                            }
                            else if (r == v2::Server::Rx::kDropped)
                                STAT_ADD(global_stats.udp_rx_drops, 1);
                            continue;
                        }
                        if (!cfg.accept_v1)
                        {
                            STAT_ADD(global_stats.udp_rx_drops, 1);
                            continue;
                        }
                        if (n < (int)sizeof(PacketHeader))
                        {
                            STAT_ADD(global_stats.udp_rx_drops, 1);
                            LOG(LOG_WARN, "Received too short packet (%d bytes) from %s",
                                n, inet_ntoa(client_addr.sin_addr));
                            continue;
                        }

                        PacketHeader *hdr = (PacketHeader *)buf;
                        if (hdr->type == PKT_DATA)
                        {
                            handleUdpToTun(cm, tun, buf, n, client_addr, hdr->session_id);
                            STAT_ADD(global_stats.udp_rx_bytes, n);
                        }
                        else
                        {
                            handleHandshake(hdr, n, buf, client_addr, sock,
                                            client_connection_sessions, cm);
                            STAT_ADD(global_stats.handshake_pkts, 1);
                        }
                    }
                    PROFILE_SCOPE_END(rx_batch_t0, global_stats.rx_userspace_cycles);
                }
                else
                {
                    STAT_ADD(global_stats.udp_recv_eagain, 1);
                    if (errno == EWOULDBLOCK || errno == EAGAIN)
                    {
                        break; // No more data to read
                    }
                    perror("recvmmsg");
                    break;
                }
                // If kernel returned fewer than batch, socket is drained
                if (rcvd < RX_BATCH)
                    break;
            }
        }
        if (FD_ISSET(tun, &rf))
        {

            int batch_count = 0;

            while (true)
            {
                PROFILE_SCOPE_START(tun_rd_t0);
                int n = read(tun, main_loop_buf, sizeof(main_loop_buf));
                PROFILE_SCOPE_END(tun_rd_t0, global_stats.tun_read_cycles);
                if (n < 0)
                {
                    STAT_ADD(global_stats.tun_read_eagain, 1);
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;
                    perror("read tun");
                    break;
                }

                if (n == 0)
                    break;
                STAT_ADD(global_stats.tun_rx_pkts, 1);
                STAT_ADD(global_stats.tun_rx_bytes, n);

                // H1: only route complete IPv4 packets (short reads / IPv6 are dropped)
                uint32_t dst_host = 0;
                if (!net::ipv4Destination(main_loop_buf, (size_t)n, dst_host))
                {
                    STAT_ADD(global_stats.tun_rx_drops, 1);
                    continue;
                }

                if (v2srv && v2srv->ownsTunIp(dst_host))
                {
                    if ((size_t)n + v2::kTransportMinLen > (size_t)TX_BUF_SIZE)
                    {
                        STAT_ADD(global_stats.tun_rx_drops, 1);
                        continue;
                    }
                    size_t v2_len = 0;
                    v2::Endpoint to;
                    PROFILE_SCOPE_START(enc_v2_t0);
                    const bool sealed = v2srv->seal(dst_host, main_loop_buf, (size_t)n, monotonicMs(),
                                                    tx_bufs[batch_count], v2_len, to);
                    PROFILE_SCOPE_END(enc_v2_t0, global_stats.enc_cycles);
                    if (!sealed)
                        continue; // session not confirmed yet
                    tx_addrs[batch_count].sin_family = AF_INET;
                    tx_addrs[batch_count].sin_addr.s_addr = to.addr;
                    tx_addrs[batch_count].sin_port = to.port;
                    tx_iovecs[batch_count].iov_base = tx_bufs[batch_count];
                    tx_iovecs[batch_count].iov_len = v2_len;
                    tx_msgs[batch_count].msg_hdr.msg_iov = &tx_iovecs[batch_count];
                    tx_msgs[batch_count].msg_hdr.msg_iovlen = 1;
                    tx_msgs[batch_count].msg_hdr.msg_name = &tx_addrs[batch_count];
                    tx_msgs[batch_count].msg_hdr.msg_namelen = sizeof(tx_addrs[batch_count]);
                    batch_count++;
                }
                else
                {
                Client *target = cm.getClientByServerIp(dst_host);
                if (!target)
                    continue;

                // Header + ciphertext + tag must fit the TX slot
                const size_t wire_len = sizeof(PacketHeader) + (size_t)n + target->tx->overhead();
                if (wire_len > (size_t)TX_BUF_SIZE)
                {
                    STAT_ADD(global_stats.tun_rx_drops, 1);
                    continue;
                }

                PacketHeader hdr;
                hdr.type = PKT_DATA;
                hdr.session_id = htonl(target->session_id); // Send the actual ID

                unsigned char *out = tx_bufs[batch_count];
                memcpy(out, &hdr, sizeof(hdr));
                PROFILE_SCOPE_START(enc_t0);
                // v1: no counter/AAD; v2 passes the header as AAD and tx_counter++ (design 01 C1/C2)
                target->tx->seal(target->tx_counter++, nullptr, 0,
                                 main_loop_buf, (size_t)n, out + sizeof(hdr));
                PROFILE_SCOPE_END(enc_t0, global_stats.enc_cycles);
                tx_iovecs[batch_count].iov_base = out;
                tx_iovecs[batch_count].iov_len = wire_len;

                tx_msgs[batch_count].msg_hdr.msg_iov = &tx_iovecs[batch_count];
                tx_msgs[batch_count].msg_hdr.msg_iovlen = 1;
                // client addr ip+port
                tx_msgs[batch_count].msg_hdr.msg_name =
                    &target->client_udp_addr;
                tx_msgs[batch_count].msg_hdr.msg_namelen =
                    sizeof(target->client_udp_addr);

                batch_count++;
                } // v1
                // ---- FLUSH CONDITIONS ----
                if (batch_count == TX_BATCH)
                {

                    PROFILE_SCOPE_START(tx_syscall_t0);
                    int sent = sendmmsg(sock, tx_msgs, batch_count, 0);

                    PROFILE_SCOPE_END(tx_syscall_t0, global_stats.tx_syscall_cycles);
                    STAT_ADD(global_stats.udp_tx_batches, 1);
                    if (sent < 0)
                    {
                        STAT_ADD(global_stats.udp_tx_drops, (batch_count));
                        perror("sendmmsg");
                        batch_count = 0;
                    }
                    else if (sent < batch_count)
                    {
                        // Drop remaining packets intentionally (UDP)
                        // Optional debug log:
                        LOG(LOG_WARN, "sendmmsg dropped %d packets",
                            (batch_count - sent));
                        STAT_ADD(global_stats.udp_tx_drops, (batch_count - sent));
                        batch_count = 0;
                    }
                    else
                    {
                        STAT_ADD(global_stats.udp_tx_pkts, sent);
                        for (int i = 0; i < sent; i++)
                        {
                            STAT_ADD(global_stats.udp_tx_bytes, tx_iovecs[i].iov_len);
                        }
                        batch_count = 0;
                    }
                }
            }
            if (batch_count > 0)
            {
                PROFILE_SCOPE_START(tx_syscall_t0);
                int sent = sendmmsg(sock, tx_msgs, batch_count, 0);

                PROFILE_SCOPE_END(tx_syscall_t0, global_stats.tx_syscall_cycles);
                STAT_ADD(global_stats.udp_tx_batches, 1);
                if (sent < 0)
                {
                    perror("sendmmsg");
                    STAT_ADD(global_stats.udp_tx_drops, (batch_count));
                    batch_count = 0;
                }
                else if (sent < batch_count)
                {
                    // Drop remaining packets intentionally (UDP)
                    // Optional debug log:
                    LOG(LOG_WARN, "sendmmsg dropped %d packets",
                        (batch_count - sent));
                    STAT_ADD(global_stats.udp_tx_drops, (batch_count - sent));
                    batch_count = 0;
                }
                else
                {
                    STAT_ADD(global_stats.udp_tx_pkts, sent);
                    for (int i = 0; i < sent; i++)
                    {
                        STAT_ADD(global_stats.udp_tx_bytes, tx_iovecs[i].iov_len);
                    }
                    batch_count = 0;
                }
            }
        }
    }
    LOG(LOG_INFO, "Shutting down");

    log_flush();
    log_shutdown();

    close(tun);
    close(sock);
    return 0;
}
