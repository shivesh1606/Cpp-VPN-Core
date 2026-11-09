// vpn_client_v2 - protocol v2 test client for Linux (design doc 02), on the shared v2::Client engine.
//
// No TUN device needed: it builds ICMP echo requests from its tunnel address itself and checks the
// echo replies, so it tests handshake, both transport directions, rekey and BYE end to end.
//
//   vpn_client_v2 --gen-key client.key            # prints the public key for allowed_clients
//   vpn_client_v2 --key client.key --server-pub <S_pub> [--host 127.0.0.1] [--port 5555]
//                 [--ping 10.8.0.1] [--count 3] [--rekey] [--drop-ack] [--offer chacha20poly1305,...]
//
// Exit code 0 = every echo got its reply (after the rekey too, with --rekey).
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <sodium.h>
#include <string>
#include <vector>

#include "config/Ini.h"
#include "crypto/CipherRegistry.h"
#include "crypto/NodeIdentity.h"
#include "protocol/v2/Client.h"

namespace
{

uint64_t nowMs()
{
    using namespace std::chrono;
    return uint64_t(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

uint16_t inetChecksum(const uint8_t *p, size_t n)
{
    uint32_t s = 0;
    for (size_t i = 0; i + 1 < n; i += 2)
        s += uint32_t(p[i]) << 8 | p[i + 1];
    if (n & 1)
        s += uint32_t(p[n - 1]) << 8;
    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);
    return uint16_t(~s);
}

// IPv4 + ICMP echo request, 56-byte payload.
std::vector<uint8_t> icmpEcho(uint32_t src, uint32_t dst, uint16_t id, uint16_t seq)
{
    std::vector<uint8_t> p(20 + 8 + 56);
    for (size_t i = 28; i < p.size(); i++)
        p[i] = uint8_t(i * 7 + seq);
    p[0] = 0x45;
    p[2] = uint8_t(p.size() >> 8);
    p[3] = uint8_t(p.size());
    p[4] = uint8_t(id >> 8);
    p[5] = uint8_t(id);
    p[8] = 64; // TTL
    p[9] = 1;  // ICMP
    for (int i = 0; i < 4; i++)
    {
        p[12 + i] = uint8_t(src >> (24 - 8 * i));
        p[16 + i] = uint8_t(dst >> (24 - 8 * i));
    }
    const uint16_t ipsum = inetChecksum(p.data(), 20);
    p[10] = uint8_t(ipsum >> 8);
    p[11] = uint8_t(ipsum);
    uint8_t *icmp = p.data() + 20;
    icmp[0] = 8; // echo request
    icmp[4] = uint8_t(id >> 8);
    icmp[5] = uint8_t(id);
    icmp[6] = uint8_t(seq >> 8);
    icmp[7] = uint8_t(seq);
    const uint16_t csum = inetChecksum(icmp, p.size() - 20);
    icmp[2] = uint8_t(csum >> 8);
    icmp[3] = uint8_t(csum);
    return p;
}

std::string ipStr(uint32_t ip)
{
    return std::to_string(ip >> 24) + "." + std::to_string((ip >> 16) & 255) + "." +
           std::to_string((ip >> 8) & 255) + "." + std::to_string(ip & 255);
}

int usage()
{
    std::fprintf(stderr,
                 "usage: vpn_client_v2 --gen-key FILE | --pubkey FILE\n"
                 "       vpn_client_v2 --key FILE --server-pub B64 [--host H] [--port P] [--ping IP]\n"
                 "                     [--count N] [--rekey] [--drop-ack] [--offer a,b]\n");
    return 2;
}

class Session
{
public:
    Session(int sock, sockaddr_in server, v2::Client &c) : sock_(sock), server_(server), c_(c) {}

    void send(const uint8_t *p, size_t n)
    {
        if (n && sendto(sock_, p, n, 0, reinterpret_cast<const sockaddr *>(&server_), sizeof(server_)) < 0)
            std::perror("sendto");
    }

    // Handshake with retries (design 02 section 4: 5 s + jitter, new msg1 each attempt).
    bool handshake(bool drop_ack, int attempts = 4)
    {
        uint8_t init[v2::kInitMaxLen];
        for (int a = 1; a <= attempts; a++)
        {
            const uint64_t t0 = nowMs();
            send(init, c_.startHandshake(t0, init));
            const uint64_t deadline = t0 + 5000 + randombytes_uniform(334);
            while (nowMs() < deadline)
            {
                if (pump(int(deadline - nowMs()), drop_ack) == v2::Client::Event::kEstablished)
                {
                    std::printf("established: hsid=%s ip=%s cipher=%s keepalive=%us rtt=%llu ms%s\n",
                                c_.handshakeId().c_str(), ipStr(c_.tunIp()).c_str(),
                                crypto::CipherRegistry::instance().find(c_.cipherId())->algorithmName(),
                                c_.keepaliveSeconds(), (unsigned long long)(nowMs() - t0),
                                drop_ack ? " (ACK deliberately not sent)" : "");
                    return true;
                }
            }
            std::printf("no HS_RESP after attempt %d\n", a);
        }
        return false;
    }

    // Waits up to `ms` for one packet and feeds it to the engine.
    v2::Client::Event pump(int ms, bool drop_ack = false)
    {
        pollfd pfd{sock_, POLLIN, 0};
        if (poll(&pfd, 1, ms) <= 0)
            return v2::Client::Event::kNone;
        uint8_t buf[2048], out[v2::kAckLen];
        const ssize_t n = recv(sock_, buf, sizeof(buf), 0);
        if (n <= 0)
            return v2::Client::Event::kNone;
        size_t out_len = 0;
        plain_len = 0;
        const auto ev = c_.receive(buf, size_t(n), nowMs(), out, out_len, plain, plain_len);
        if (ev == v2::Client::Event::kEstablished && !drop_ack)
            send(out, out_len);
        if (ev == v2::Client::Event::kKeepalive)
            keepalives++;
        return ev;
    }

    // Sends `count` echo requests to `dst`; returns how many replies matched.
    int ping(uint32_t dst, int count)
    {
        int ok = 0;
        for (int seq = 1; seq <= count; seq++)
        {
            const uint16_t id = uint16_t(randombytes_random());
            const auto req = icmpEcho(c_.tunIp(), dst, id, uint16_t(seq));
            uint8_t wire[256];
            const uint64_t t0 = nowMs();
            send(wire, c_.sealData(req.data(), req.size(), t0, wire));
            bool got = false;
            while (!got && nowMs() < t0 + 3000)
            {
                if (pump(int(t0 + 3000 - nowMs())) != v2::Client::Event::kData || plain_len < 28)
                    continue;
                const uint32_t src = uint32_t(plain[12]) << 24 | uint32_t(plain[13]) << 16 |
                                     uint32_t(plain[14]) << 8 | plain[15];
                const bool match = plain[9] == 1 && plain[20] == 0 &&
                                   (uint16_t(plain[24] << 8 | plain[25]) == id) &&
                                   (uint16_t(plain[26] << 8 | plain[27]) == seq) &&
                                   plain_len == req.size() &&
                                   std::memcmp(plain + 28, req.data() + 28, req.size() - 28) == 0;
                if (match)
                {
                    std::printf("echo reply seq=%d %s->%s hsid=%s rtt=%llu ms\n", seq, ipStr(src).c_str(),
                                ipStr(c_.tunIp()).c_str(), c_.handshakeId().c_str(),
                                (unsigned long long)(nowMs() - t0));
                    got = true;
                    ok++;
                }
            }
            if (!got)
                std::printf("FAIL: no echo reply for seq=%d\n", seq);
        }
        return ok;
    }

    uint8_t plain[2048];
    size_t plain_len = 0;
    int keepalives = 0;

private:
    int sock_;
    sockaddr_in server_;
    v2::Client &c_;
};

} // namespace

int main(int argc, char **argv)
{
    std::string key_path, server_pub, host = "127.0.0.1", ping_ip, offer = "chacha20poly1305,aes256gcm";
    int port = 5555, count = 3;
    bool rekey = false, drop_ack = false;
    for (int i = 1; i < argc; i++)
    {
        const std::string a = argv[i];
        const bool v = i + 1 < argc;
        if ((a == "--gen-key" || a == "--pubkey") && v)
        {
            crypto::NodeIdentity id;
            std::string err;
            const bool ok = a == "--gen-key" ? crypto::generateNodeKey(argv[i + 1], false, id, err)
                                             : crypto::loadNodeKey(argv[i + 1], id, err);
            if (!ok)
            {
                std::fprintf(stderr, "error: %s\n", err.c_str());
                return 1;
            }
            std::printf("%s\n", id.publicKeyBase64Url().c_str());
            return 0;
        }
        else if (a == "--key" && v) key_path = argv[++i];
        else if (a == "--server-pub" && v) server_pub = argv[++i];
        else if (a == "--host" && v) host = argv[++i];
        else if (a == "--port" && v) port = std::atoi(argv[++i]);
        else if (a == "--ping" && v) ping_ip = argv[++i];
        else if (a == "--count" && v) count = std::atoi(argv[++i]);
        else if (a == "--offer" && v) offer = argv[++i];
        else if (a == "--rekey") rekey = true;
        else if (a == "--drop-ack") drop_ack = true;
        else return usage();
    }
    if (key_path.empty() || server_pub.empty())
        return usage();

    crypto::NodeIdentity me;
    std::string err;
    if (!crypto::loadNodeKey(key_path, me, err))
    {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 1;
    }
    v2::ClientConfig cc;
    std::memcpy(cc.static_priv, me.privateKey(), 32);
    if (!crypto::fromBase64Url(server_pub, cc.server_pub, 32))
    {
        std::fprintf(stderr, "error: --server-pub is not a 43-character base64url key\n");
        return 2;
    }
    cc.offer.clear();
    for (const auto &name : config::splitList(offer))
        for (const auto &b : crypto::CipherRegistry::instance().all())
            if (name == b->algorithmName() &&
                std::find(cc.offer.begin(), cc.offer.end(), b->algorithmId()) == cc.offer.end())
                cc.offer.push_back(b->algorithmId());
    v2::Client client(cc);

    const int sock = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(uint16_t(port));
    if (sock < 0 || inet_pton(AF_INET, host.c_str(), &server.sin_addr) != 1)
        return usage();
    std::printf("client key %s -> %s:%d\n", me.publicKeyBase64Url().c_str(), host.c_str(), port);

    Session s(sock, server, client);
    if (!s.handshake(drop_ack))
    {
        std::printf("FAIL: handshake\n");
        return 1;
    }
    int expected = 0, got = 0;
    in_addr dst{};
    if (!ping_ip.empty() && inet_pton(AF_INET, ping_ip.c_str(), &dst) == 1)
    {
        got += s.ping(ntohl(dst.s_addr), count);
        expected += count;
        if (rekey)
        {
            const std::string before = client.handshakeId();
            const uint32_t ip_before = client.tunIp();
            if (!s.handshake(false))
            {
                std::printf("FAIL: rekey handshake\n");
                return 1;
            }
            std::printf("rekeyed: hsid %s -> %s, ip %s -> %s\n", before.c_str(), client.handshakeId().c_str(),
                        ipStr(ip_before).c_str(), ipStr(client.tunIp()).c_str());
            if (client.handshakeId() == before || client.tunIp() != ip_before)
            {
                std::printf("FAIL: rekey must change keys and keep the address\n");
                return 1;
            }
            got += s.ping(ntohl(dst.s_addr), count);
            expected += count;
        }
    }
    uint8_t bye[64];
    s.send(bye, client.sealBye(nowMs(), bye));
    const auto &st = client.stats();
    std::printf("client drops: resp %llu fmt %llu no_session %llu replay %llu auth %llu\n",
                (unsigned long long)st.resp_drop, (unsigned long long)st.tr_drop_format,
                (unsigned long long)st.tr_drop_no_session, (unsigned long long)st.tr_drop_replay,
                (unsigned long long)st.tr_drop_auth);
    if (got == expected)
    {
        std::printf("PASS: v2 handshake%s + %d/%d echo replies%s + BYE\n", drop_ack ? " (no ACK)" : "",
                    got, expected, rekey ? " across a rekey" : "");
        return 0;
    }
    std::printf("FAIL: %d/%d echo replies\n", got, expected);
    return 1;
}
