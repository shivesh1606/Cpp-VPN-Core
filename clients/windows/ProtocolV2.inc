// ProtocolV2.inc - protocol v2 for the Windows client (design doc 02), on the shared engine
// protocol/v2/Client.{h,cpp}. Included by main.cpp after the v1 code; uses its Config, logging,
// Wintun function pointers and g_running.
//
//   key file       one line, base64url X25519 private key (same format as vpn_server --gen-key)
//   handshake      HS_INIT, retry every 5 s + jitter with a fresh msg1 (section 4)
//   tunnel         DATA both ways; KEEPALIVE when idle; client-initiated rekey after rekey_after
//                  seconds while traffic keeps flowing under the old key; reconnect on BYE/expiry

#include "auth/Bundle.h"
#include "crypto/Base64Url.h"
#include "crypto/CipherRegistry.h"
#include "protocol/v2/Client.h"

static uint64_t v2NowMs() { return (uint64_t)now_ms(); }

// ---------------- key files ----------------

static bool v2GenKey(const std::string &path)
{
    uint8_t sk[32], pk[32];
    randombytes_buf(sk, sizeof(sk));
    crypto_scalarmult_base(pk, sk);
    // CREATE_NEW: never overwrite an existing identity. The file inherits the ACL of its folder
    // (by default the user's profile is private to the user); keep it out of shared folders.
    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        std::fprintf(stderr, "error: cannot create %s (%s)\n", path.c_str(),
                     GetLastError() == ERROR_FILE_EXISTS ? "already exists" : "access denied or bad path");
        sodium_memzero(sk, sizeof(sk));
        return false;
    }
    std::string line = crypto::toBase64Url(sk, sizeof(sk)) + "\n";
    DWORD written = 0;
    const BOOL ok = WriteFile(h, line.data(), (DWORD)line.size(), &written, nullptr) && written == line.size();
    CloseHandle(h);
    sodium_memzero(sk, sizeof(sk));
    sodium_memzero(&line[0], line.size());
    if (!ok)
        return false;
    std::fprintf(stderr, "wrote %s. Public key (add it to the server's allowed_clients):\n", path.c_str());
    std::printf("%s\n", crypto::toBase64Url(pk, sizeof(pk)).c_str());
    return true;
}

static bool v2LoadKey(const std::string &path, uint8_t sk[32])
{
    std::ifstream f(path, std::ios::binary);
    std::string text;
    if (!f || !std::getline(f, text))
    {
        LOG_E("Cannot read client key %s (create one with --gen-key %s)", path.c_str(), path.c_str());
        return false;
    }
    text = trim(text);
    const bool ok = crypto::fromBase64Url(text, sk, 32);
    sodium_memzero(&text[0], text.size());
    if (!ok)
        LOG_E("%s is not a client key (expected 43 base64url characters)", path.c_str());
    return ok;
}

// --bundle: everything a v2 connection needs, from vpnctl (design 03 section 5). The bundle holds
// the device private key: keep the file private.
static bool v2ApplyBundle(Config &cfg)
{
    if (sodium_init() < 0)
        return false;
    std::string text = cfg.bundle;
    if (text.rfind(auth::kBundleUriPrefix, 0) != 0)
    {
        std::ifstream f(cfg.bundle, std::ios::binary);
        if (!f)
        {
            LOG_E("Cannot read bundle file %s", cfg.bundle.c_str());
            return false;
        }
        text.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    }
    auth::Bundle b;
    std::string err;
    if (!auth::bundleFromText(text, b, err))
    {
        LOG_E("Bundle: %s", err.c_str());
        return false;
    }
    const auth::BundleNode *n = &b.nodes[0];
    for (const auto &x : b.nodes)
        if (x.id == cfg.node)
            n = &x;
    if (!cfg.node.empty() && n->id != cfg.node)
    {
        LOG_E("Node '%s' is not in the bundle", cfg.node.c_str());
        return false;
    }
    cfg.protocol = "v2";
    cfg.server = n->host;
    cfg.port = n->port;
    cfg.server_pub = crypto::toBase64Url(n->pub, 32);
    std::memcpy(cfg.device_sk, b.device_sk, 32);
    cfg.ticket = b.ticket;
    cfg.from_bundle = true;
    LOG_I("Bundle: node %s (%s:%u) of %zu, ticket %zu B", n->id.c_str(), n->host.c_str(), n->port,
          b.nodes.size(), b.ticket.size());
    return true;
}

static bool v2MakeClientConfig(const Config &cfg, v2::ClientConfig &cc)
{
    if (sodium_init() < 0)
        return false;
    if (cfg.from_bundle)
        std::memcpy(cc.static_priv, cfg.device_sk, 32);
    else if (!v2LoadKey(cfg.client_key, cc.static_priv))
        return false;
    cc.ticket = cfg.ticket;
    if (!crypto::fromBase64Url(cfg.server_pub, cc.server_pub, 32))
    {
        LOG_E("server_pub must be the node's 43-character public key (vpn_server --pubkey on the node)");
        return false;
    }
    cc.offer.clear();
    std::string list = cfg.offer + ",";
    for (size_t p = 0, q; (q = list.find(',', p)) != std::string::npos; p = q + 1)
    {
        const std::string name = trim(list.substr(p, q - p));
        for (const auto &b : crypto::CipherRegistry::instance().all())
            if (name == b->algorithmName() && !b->insecure() &&
                std::find(cc.offer.begin(), cc.offer.end(), b->algorithmId()) == cc.offer.end())
                cc.offer.push_back(b->algorithmId());
    }
    if (cc.offer.empty())
    {
        LOG_E("offer lists no cipher this build supports (chacha20poly1305, aes256gcm)");
        return false;
    }
    return true;
}

static std::string v2Ip(uint32_t ip)
{
    char s[INET_ADDRSTRLEN];
    in_addr a{};
    a.s_addr = htonl(ip);
    inet_ntop(AF_INET, &a, s, sizeof(s));
    return s;
}

static void v2Send(SOCKET sock, const sockaddr_in &server, const uint8_t *p, size_t n)
{
    if (n)
        sendto(sock, (const char *)p, (int)n, 0, (const sockaddr *)&server, sizeof(server));
}

// Feeds one received datagram to the engine; sends the ACK when a handshake completes.
static v2::Client::Event v2Receive(SOCKET sock, const sockaddr_in &server, v2::Client &c,
                                   const uint8_t *buf, int n, uint8_t *plain, size_t &plain_len)
{
    uint8_t ack[v2::kAckLen];
    size_t ack_len = 0;
    const auto ev = c.receive(buf, (size_t)n, v2NowMs(), ack, ack_len, plain, plain_len);
    if (ev == v2::Client::Event::kEstablished)
        v2Send(sock, server, ack, ack_len);
    return ev;
}

static bool v2Handshake(SOCKET sock, const sockaddr_in &server, v2::Client &c)
{
    for (int attempt = 1; attempt <= 4 && g_running; ++attempt)
    {
        uint8_t init[v2::kInitMaxLen];
        const double t0 = now_ms();
        v2Send(sock, server, init, c.startHandshake(v2NowMs(), init));
        LOG_I("Sent HS_INIT (attempt %d/4)", attempt);
        const double deadline = t0 + 5000 + randombytes_uniform(334);
        while (g_running && now_ms() < deadline)
        {
            fd_set rf;
            FD_ZERO(&rf);
            FD_SET(sock, &rf);
            const long left = (long)(deadline - now_ms());
            timeval tv{left / 1000, (left % 1000) * 1000};
            if (select(0, &rf, nullptr, nullptr, &tv) <= 0)
                continue;
            uint8_t buf[2048], plain[2048];
            size_t plain_len = 0;
            const int n = recv(sock, (char *)buf, sizeof(buf), 0);
            if (n > 0 && v2Receive(sock, server, c, buf, n, plain, plain_len) == v2::Client::Event::kEstablished)
            {
                LOG_I("v2 established: hsid=%s ip=%s cipher=%s keepalive=%us HS_INIT->HS_RESP=%.2f ms (attempt %d)",
                      c.handshakeId().c_str(), v2Ip(c.tunIp()).c_str(),
                      crypto::CipherRegistry::instance().find(c.cipherId())->algorithmName(),
                      c.keepaliveSeconds(), now_ms() - t0, attempt);
                return true;
            }
        }
    }
    return false;
}

// Rekey and keepalive timers shared by probe and tunnel mode. Returns false when the session is
// lost (rekey did not complete before reject-after).
struct V2Timers
{
    uint64_t rekey_started = 0;
    int rekeys = 0, keepalives_sent = 0;

    bool run(SOCKET sock, const sockaddr_in &server, v2::Client &c, const Config &cfg)
    {
        const uint64_t now = v2NowMs();
        uint8_t buf[v2::kInitMaxLen];
        if (c.sessionAgeMs(now) >= uint64_t(cfg.rekey_after) * 1000 &&
            (!c.handshakeInFlight() || now - rekey_started >= 5000))
        {
            rekey_started = now; // new msg1 every 5 s until the HS_RESP arrives
            v2Send(sock, server, buf, c.startHandshake(now, buf));
            LOG_I("Rekey: sent HS_INIT (session age %llu s)", (unsigned long long)(c.sessionAgeMs(now) / 1000));
        }
        if (c.sessionAgeMs(now) >= 180000)
        {
            LOG_W("Session key older than 180 s and rekey failed: reconnecting");
            return false;
        }
        const uint64_t ka = uint64_t(c.keepaliveSeconds() ? c.keepaliveSeconds() : cfg.keepalive_interval) * 1000;
        if (now - c.lastSendMs() >= ka)
        {
            v2Send(sock, server, buf, c.sealKeepalive(now, buf));
            keepalives_sent++;
        }
        return true;
    }
};

static int runProbeV2(const Config &cfg)
{
    v2::ClientConfig cc;
    if (!v2MakeClientConfig(cfg, cc))
        return 1;
    v2::Client c(cc);
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons((u_short)cfg.port);
    if (sock == INVALID_SOCKET || inet_pton(AF_INET, cfg.server.c_str(), &server.sin_addr) != 1)
    {
        LOG_E("Invalid server IP: %s", cfg.server.c_str());
        return 1;
    }
    LOG_I("Client public key %s", crypto::toBase64Url(c.publicKey(), 32).c_str());
    if (!v2Handshake(sock, server, c))
    {
        LOG_E("PROBE FAIL: no HS_RESP from %s:%d after 4 attempts. The node answers only authorized "
              "clients: key not in allowed_clients, or ticket rejected/expired/revoked (the server log names "
              "the reason), or server_pub is not the node's key", cfg.server.c_str(), cfg.port);
        closesocket(sock);
        return 2;
    }
    const std::string first = c.handshakeId();
    V2Timers timers;
    int server_keepalives = 0;
    const double end = now_ms() + cfg.probe_duration * 1000.0;
    std::string last_id = first;
    while (g_running && now_ms() < end)
    {
        if (!timers.run(sock, server, c, cfg))
            break;
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(sock, &rf);
        timeval tv{0, 200000};
        if (select(0, &rf, nullptr, nullptr, &tv) > 0)
        {
            uint8_t buf[2048], plain[2048];
            size_t plain_len = 0;
            const int n = recv(sock, (char *)buf, sizeof(buf), 0);
            if (n <= 0)
                continue;
            const auto ev = v2Receive(sock, server, c, buf, n, plain, plain_len);
            if (ev == v2::Client::Event::kKeepalive)
                server_keepalives++;
            else if (ev == v2::Client::Event::kEstablished)
            {
                timers.rekeys++;
                LOG_I("Rekeyed: hsid %s -> %s, ip %s", last_id.c_str(), c.handshakeId().c_str(), v2Ip(c.tunIp()).c_str());
                last_id = c.handshakeId();
            }
            else if (ev == v2::Client::Event::kBye)
            {
                LOG_W("Server sent BYE");
                break;
            }
        }
    }
    uint8_t bye[64];
    const bool still_up = c.established();
    const std::string ip = v2Ip(c.tunIp()); // before BYE clears the session
    v2Send(sock, server, bye, c.sealBye(v2NowMs(), bye));
    closesocket(sock);
    if (!still_up)
    {
        LOG_E("PROBE FAIL: session lost");
        return 3;
    }
    LOG_I("PROBE OK (v2): ip=%s hsid=%s rekeys=%d keepalives sent=%d received=%d drops: resp %llu auth %llu replay %llu",
          ip.c_str(), last_id.c_str(), timers.rekeys, timers.keepalives_sent, server_keepalives,
          (unsigned long long)c.stats().resp_drop, (unsigned long long)c.stats().tr_drop_auth,
          (unsigned long long)c.stats().tr_drop_replay);
    return 0;
}

// Tunnel loop. Returns 0 on Ctrl+C, 1 to reconnect.
static int runTunnelV2(SOCKET sock, const sockaddr_in &server, WINTUN_SESSION_HANDLE wintun_session,
                       v2::Client &c, const Config &cfg)
{
    HANDLE wintun_event = pGetReadWaitEvent(wintun_session);
    WSAEVENT udp_event = WSACreateEvent();
    WSAEventSelect(sock, udp_event, FD_READ);
    HANDLE wait_handles[2] = {wintun_event, (HANDLE)udp_event};
    static uint8_t io_buf[2048], plain[2048];
    V2Timers timers;
    double last_recv = now_ms();
    int result = 0;
    LOG_I("VPN tunnel active (protocol v2, hsid=%s) - Ctrl+C to disconnect", c.handshakeId().c_str());

    while (g_running)
    {
        const DWORD wait = WaitForMultipleObjects(2, wait_handles, FALSE, 1000);

        // TUN -> UDP
        DWORD pkt_size;
        BYTE *pkt;
        while ((pkt = pReceivePacket(wintun_session, &pkt_size)) != nullptr)
        {
            if (pkt_size + v2::kTransportMinLen <= sizeof(io_buf))
                v2Send(sock, server, io_buf, c.sealData(pkt, pkt_size, v2NowMs(), io_buf));
            pReleaseReceivePacket(wintun_session, pkt);
        }

        // UDP -> TUN
        if (wait == WAIT_OBJECT_0 + 1)
        {
            WSAResetEvent(udp_event);
            int n;
            while ((n = recv(sock, (char *)io_buf, sizeof(io_buf), 0)) > 0)
            {
                size_t plain_len = 0;
                const auto ev = v2Receive(sock, server, c, io_buf, n, plain, plain_len);
                if (ev == v2::Client::Event::kNone)
                    continue;
                last_recv = now_ms(); // authenticated: the server is alive
                if (ev == v2::Client::Event::kData)
                {
                    BYTE *out = pAllocateSendPacket(wintun_session, (DWORD)plain_len);
                    if (out)
                    {
                        memcpy(out, plain, plain_len);
                        pSendPacket(wintun_session, out);
                    }
                }
                else if (ev == v2::Client::Event::kEstablished)
                    LOG_I("Rekeyed: hsid=%s", c.handshakeId().c_str());
                else if (ev == v2::Client::Event::kBye)
                {
                    LOG_W("Server ended the session (BYE): reconnecting");
                    result = 1;
                    break;
                }
            }
            if (result)
                break;
        }

        if (!timers.run(sock, server, c, cfg))
        {
            result = 1;
            break;
        }
        // v2 servers send KEEPALIVE to idle clients, so silence means the path or server is gone.
        const int silence_limit = cfg.timeout > 0 ? cfg.timeout : 3 * std::max<int>(c.keepaliveSeconds(), 15);
        if (now_ms() - last_recv > silence_limit * 1000.0)
        {
            LOG_W("Nothing from the server for %d s: reconnecting", silence_limit);
            result = 1;
            break;
        }
    }
    WSACloseEvent(udp_event);
    return result;
}
