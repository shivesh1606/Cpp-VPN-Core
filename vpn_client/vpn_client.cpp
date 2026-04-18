#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <winioctl.h>
#define ioctl DeviceIoControl
#define close closesocket
#define select select
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#include "crypto/DiffieHellman.h"
#include "crypto/XorCipher.h"
#include "net/socket/SocketManager.h"
#include "net/tun/TunDevice.h"
#include "protocol/Handshake.h"
#include "utils/logger.h"

static volatile sig_atomic_t g_shutdown = 0;

void handle_sigint(int)
{
    g_shutdown = 1;
}

bool configureTun(const char *ifname, const char *ip, const char *netmask)
{
    int ctrl = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctrl < 0)
    {
        LOG(LOG_ERROR, "Failed to open control socket: %s", strerror(errno));
        return false;
    }

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_addr.sa_family = AF_INET;

    if (inet_pton(AF_INET, ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr) != 1)
    {
        LOG(LOG_ERROR, "Invalid IP address: %s", ip);
        close(ctrl);
        return false;
    }
    if (ioctl(ctrl, SIOCSIFADDR, &ifr) < 0)
    {
        LOG(LOG_ERROR, "Failed to assign IP %s to %s: %s", ip, ifname, strerror(errno));
        close(ctrl);
        return false;
    }

    if (inet_pton(AF_INET, netmask, &((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr) != 1)
    {
        LOG(LOG_ERROR, "Invalid netmask: %s", netmask);
        close(ctrl);
        return false;
    }
    if (ioctl(ctrl, SIOCSIFNETMASK, &ifr) < 0)
    {
        LOG(LOG_ERROR, "Failed to assign netmask %s to %s: %s", netmask, ifname, strerror(errno));
        close(ctrl);
        return false;
    }

    if (ioctl(ctrl, SIOCGIFFLAGS, &ifr) < 0)
    {
        LOG(LOG_ERROR, "Failed to get flags for %s: %s", ifname, strerror(errno));
        close(ctrl);
        return false;
    }
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(ctrl, SIOCSIFFLAGS, &ifr) < 0)
    {
        LOG(LOG_ERROR, "Failed to bring up interface %s: %s", ifname, strerror(errno));
        close(ctrl);
        return false;
    }

    close(ctrl);
    return true;
}

bool performHandshake(int sock, const struct sockaddr_in &server_addr, const char *tun_name,
                      uint8_t &xor_key, uint32_t &session_id, uint32_t &assigned_tun_ip)
{
    uint32_t client_magic = static_cast<uint32_t>(randomNumGen(100000, 999999));
    uint32_t secret_b = static_cast<uint32_t>(randomNumGen(1000, 5000));
    uint32_t yc = static_cast<uint32_t>(modexp(G, secret_b, P));

    HelloPacket hello{};
    hello.hdr.type = PKT_HELLO;
    hello.hdr.session_id = 0;
    hello.client_magic = client_magic;
    hello.yc = htonl(yc);

    const int max_attempts = 4;
    for (int attempt = 1; attempt <= max_attempts && !g_shutdown; ++attempt)
    {
        ssize_t sent = sendto(sock,
                              reinterpret_cast<char *>(&hello),
                              sizeof(hello),
                              0,
                              reinterpret_cast<const struct sockaddr *>(&server_addr),
                              sizeof(server_addr));
        if (sent != sizeof(hello))
        {
            LOG(LOG_WARN, "Handshake HELLO send failed (attempt %d): %s", attempt, strerror(errno));
        }
        else
        {
            LOG(LOG_INFO, "Sent HELLO to server (attempt %d)", attempt);
        }

        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(sock, &rf);
        struct timeval timeout{5, 0};
        int ready = select(sock + 1, &rf, nullptr, nullptr, &timeout);
        if (ready <= 0)
        {
            if (ready < 0)
                LOG(LOG_WARN, "Handshake select failed: %s", strerror(errno));
            continue;
        }

        unsigned char buffer[2048];
        struct sockaddr_in from{};
        socklen_t from_len = sizeof(from);
        ssize_t received = recvfrom(sock,
                                    buffer,
                                    sizeof(buffer),
                                    0,
                                    reinterpret_cast<struct sockaddr *>(&from),
                                    &from_len);
        if (received < 0)
        {
            LOG(LOG_WARN, "Handshake recvfrom failed: %s", strerror(errno));
            continue;
        }

        if (received < static_cast<ssize_t>(sizeof(PacketHeader)))
        {
            LOG(LOG_WARN, "Received malformed handshake packet (%zd bytes)", received);
            continue;
        }

        PacketHeader *hdr = reinterpret_cast<PacketHeader *>(buffer);
        if (hdr->type != PKT_WELCOME)
        {
            LOG(LOG_WARN, "Received unexpected packet type %u during handshake", hdr->type);
            continue;
        }

        if (received < static_cast<ssize_t>(sizeof(WelcomePacket)))
        {
            LOG(LOG_WARN, "Received incomplete WELCOME packet (%zd bytes)", received);
            continue;
        }

        WelcomePacket *welcome = reinterpret_cast<WelcomePacket *>(buffer);
        session_id = ntohl(welcome->hdr.session_id);
        assigned_tun_ip = ntohl(welcome->assigned_tun_ip);
        uint32_t ys = ntohl(welcome->ys);

        uint32_t shared_secret = static_cast<uint32_t>(modexp(ys, secret_b, P));
        xor_key = calculateXORKey(shared_secret);

        ClientAckPacket ack{};
        ack.hdr.type = PKT_CLIENT_ACK;
        ack.hdr.session_id = htonl(session_id);

        ssize_t ack_sent = sendto(sock,
                                 reinterpret_cast<char *>(&ack),
                                 sizeof(ack),
                                 0,
                                 reinterpret_cast<const struct sockaddr *>(&server_addr),
                                 sizeof(server_addr));
        if (ack_sent != sizeof(ack))
        {
            LOG(LOG_WARN, "Failed to send CLIENT_ACK: %s", strerror(errno));
            continue;
        }

        struct in_addr addr{};
        addr.s_addr = htonl(assigned_tun_ip);
        char assigned_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, assigned_ip_str, sizeof(assigned_ip_str));

        LOG(LOG_INFO, "Handshake completed: session_id=%u assigned_tun_ip=%s xor_key=%u",
            session_id, assigned_ip_str, xor_key);

        std::string tun_ip = std::string(assigned_ip_str);
        if (!configureTun(tun_name, tun_ip.c_str(), "255.255.255.0"))
        {
            LOG(LOG_WARN, "Could not configure TUN device %s automatically", tun_name);
        }

        return true;
    }

    return false;
}

int main(int argc, char *argv[])
{
    const char *server_ip = "127.0.0.1";
    uint16_t server_port = 5555;
    const char *tun_name = "tun0";

    if (argc >= 2)
        server_ip = argv[1];
    if (argc >= 3)
        server_port = static_cast<uint16_t>(std::stoi(argv[2]));
    if (argc >= 4)
        tun_name = argv[3];

    log_init();
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    srand(static_cast<unsigned int>(time(nullptr) ^ getpid()));

    int tun_fd = TunDevice::create(tun_name);
    if (tun_fd < 0)
    {
        std::cerr << "[ERROR] Failed to create TUN device " << tun_name << "\n";
        return 1;
    }

    int sock = SocketManager::createUdpSocket(0);
    if (sock < 0)
    {
        std::cerr << "[ERROR] Failed to create UDP socket\n";
        close(tun_fd);
        return 1;
    }

    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) != 1)
    {
        std::cerr << "[ERROR] Invalid server IP: " << server_ip << "\n";
        close(tun_fd);
        close(sock);
        return 1;
    }

    fcntl(sock, F_SETFL, O_NONBLOCK);
    fcntl(tun_fd, F_SETFL, O_NONBLOCK);

    uint8_t xor_key = 0;
    uint32_t session_id = 0;
    uint32_t assigned_tun_ip = 0;

    if (!performHandshake(sock, server_addr, tun_name, xor_key, session_id, assigned_tun_ip))
    {
        std::cerr << "[ERROR] Handshake failed\n";
        close(tun_fd);
        close(sock);
        return 1;
    }

    LOG(LOG_INFO, "VPN client connected to %s:%u", server_ip, server_port);

    unsigned char udp_buf[2000];
    unsigned char tun_buf[2000];

    while (!g_shutdown)
    {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(sock, &rf);
        FD_SET(tun_fd, &rf);
        int nf = std::max(sock, tun_fd) + 1;

        int ready = select(nf, &rf, nullptr, nullptr, nullptr);
        if (ready < 0)
        {
            if (errno == EINTR)
                continue;
            perror("select");
            break;
        }

        if (FD_ISSET(sock, &rf))
        {
            struct sockaddr_in src_addr{};
            socklen_t src_len = sizeof(src_addr);
            ssize_t n = recvfrom(sock,
                                 udp_buf,
                                 sizeof(udp_buf),
                                 0,
                                 reinterpret_cast<struct sockaddr *>(&src_addr),
                                 &src_len);
            if (n < 0)
            {
                if (errno != EWOULDBLOCK && errno != EAGAIN)
                    perror("recvfrom");
            }
            else if (n >= static_cast<ssize_t>(sizeof(PacketHeader)))
            {
                PacketHeader *hdr = reinterpret_cast<PacketHeader *>(udp_buf);
                if (hdr->type == PKT_DATA)
                {
                    int payload_len = static_cast<int>(n - sizeof(PacketHeader));
                    char decrypted[2000];
                    XorCipher &enc = XorCipher::getInstance();
                    enc.crypt(reinterpret_cast<char *>(udp_buf + sizeof(PacketHeader)), payload_len, decrypted, xor_key);

                    ssize_t written = write(tun_fd, decrypted, payload_len);
                    if (written < 0)
                    {
                        perror("write tun");
                    }
                }
                else
                {
                    LOG(LOG_DEBUG, "Ignoring unexpected packet type %u from server", hdr->type);
                }
            }
        }

        if (FD_ISSET(tun_fd, &rf))
        {
            ssize_t n = read(tun_fd, tun_buf, sizeof(tun_buf));
            if (n < 0)
            {
                if (errno != EWOULDBLOCK && errno != EAGAIN)
                    perror("read tun");
            }
            else if (n > 0)
            {
                PacketHeader hdr{};
                hdr.type = PKT_DATA;
                hdr.session_id = htonl(session_id);
                unsigned char out_buf[2000];
                std::memcpy(out_buf, &hdr, sizeof(hdr));
                XorCipher &enc = XorCipher::getInstance();
                enc.crypt(reinterpret_cast<char *>(tun_buf), static_cast<int>(n), reinterpret_cast<char *>(out_buf + sizeof(hdr)), xor_key);

                ssize_t sent = sendto(sock,
                                      out_buf,
                                      sizeof(hdr) + n,
                                      0,
                                      reinterpret_cast<const struct sockaddr *>(&server_addr),
                                      sizeof(server_addr));
                if (sent < 0)
                {
                    perror("sendto");
                }
            }
        }
    }

    LOG(LOG_INFO, "VPN client shutting down");
    close(tun_fd);
    close(sock);
    log_flush();
    log_shutdown();
    return 0;
}
