// server.cpp -- Minimal UDP <-> TUN forwarder (for testing only)

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <algorithm> // for std::max
#include "Encryption.h"
#include "Client_Manager.h"
#include "handshake.h"

int create_tun(const char *name = "tun0")
{
    struct ifreq ifr{};
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
    {
        perror("open /dev/net/tun");
        exit(1);
    }
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0; // ensure null termination
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0)
    {
        perror("ioctl TUNSETIFF");
        exit(1);
    }
    std::cout << "[+] TUN created: " << ifr.ifr_name << "\n";
    return fd;
}

int main()
{
    std::vector<SessionState> client_connection_sessions;
    int tun = create_tun("tun0");
    // Example usage in your TUN/UDP loop
    Encryption &enc = Encryption::getInstance();
    ClientManager cm(100, "10.8.0.2");
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return 1;
    }

    struct sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = INADDR_ANY;
    srv.sin_port = htons(5555);

    if (bind(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0)
    {
        perror("bind");
        return 1;
    }

    std::cout << "[+] UDP listening on 0.0.0.0:5555\n";

    unsigned char buf[2000];
    char temp[2000];
    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    char client_ip[64];
    Client *client, *target;
    while (true)
    {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(sock, &rf);
        FD_SET(tun, &rf);

        int nf = std::max(sock, tun) + 1;
        int ret = select(nf, &rf, nullptr, nullptr, nullptr);
        if (ret < 0)
        {
            perror("select");
            continue;
        }

        if (FD_ISSET(sock, &rf))
        {
            int n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&client_addr, &client_len);
            if (n > 0)
            {
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
                std::cout << "[IN] Received " << n << " bytes from " << client_ip
                          << ":" << ntohs(client_addr.sin_port) << "\n";
                std::cout << "[UDP→TUN] " << n << " bytes\n";
                // Decrypt data after receiving UDP
                if (n < (int)sizeof(PacketHeader))
                {
                    std::cout << "[WARN] Packet too small for header\n";
                    continue;
                }

                PacketHeader *hdr = (PacketHeader *)buf;
                if (hdr->type == PKT_HELLO)
                {
                    if (n < (int)sizeof(HelloPacket))
                    {
                        std::cout << "[WARN] Short HELLO packet\n";
                        continue;
                    }

                    HelloPacket *hello = (HelloPacket *)buf;
                    //
                    std::cout << "[INFO] HELLO packet received, client_magic="
                              << hello->client_magic << "\n";

                    uint32_t assigned_ip = ntohl(inet_addr("10.8.0.12"));

                    WelcomePacket welcome{};
                    welcome.hdr.type = PKT_WELCOME;
                    welcome.hdr.session_id = hello->client_magic; // unused for now
                    welcome.assigned_tun_ip = htonl(assigned_ip);

                    // Create SessionState for this client
                    SessionState session{};
                    session.client_udp_addr = client_addr;
                    session.assigned_tun_ip = assigned_ip;
                    session.client_magic = hello->client_magic;
                    client_connection_sessions.push_back(session);
                    sendto(sock,
                           (char *)&welcome,
                           sizeof(welcome),
                           0,
                           (struct sockaddr *)&client_addr,
                           sizeof(client_addr));
                    in_addr a{};
                    a.s_addr = htonl(assigned_ip);
                    std::cout << "[INFO] Sent WELCOME packet, assigned_ip="
                            << inet_ntoa(a) << "\n";

                }
                else if (hdr->type == PKT_CLIENT_ACK)
                {
                    if (n < (int)sizeof(ClientAckPacket))
                    {
                        std::cout << "[WARN] Short ClientAckPacket packet\n";
                        continue;
                    }

                    std::cout << "[INFO] CLIENT_ACK packet received\n";
                    // check if session exists, etc.
                    ClientAckPacket *ack = (ClientAckPacket *)buf;
                    SessionState *session = nullptr;
                    for (auto &s : client_connection_sessions)
                    {
                        if (s.client_udp_addr.sin_addr.s_addr == client_addr.sin_addr.s_addr &&
                            s.client_udp_addr.sin_port == client_addr.sin_port)
                        {
                            session = &s;
                            break;
                        }
                    }
                    if (session == nullptr)
                    {
                        std::cout << "[WARN] CLIENT_ACK from unknown client\n";
                        continue;
                    }
                    // Add client to ClientManager
                    cm.addClient(client_addr, session->assigned_tun_ip, ack->xor_key);
                    // Delete session state as handshake is complete
                    client_connection_sessions.erase(
                        std::remove_if(client_connection_sessions.begin(),
                                       client_connection_sessions.end(),
                                       [&](const SessionState &s)
                                       {
                                           return s.client_udp_addr.sin_addr.s_addr == session->client_udp_addr.sin_addr.s_addr &&
                                                  s.client_udp_addr.sin_port == session->client_udp_addr.sin_port;
                                       }),
                        client_connection_sessions.end());
                }
                else if (hdr->type == PKT_DATA)
                {
                    std::cout << "[INFO] DATA packet received\n";
                    client = cm.getClientByUdp(client_addr);

                    if (!client)
                    {
                        std::cout << "[WARN] DATA packet from unknown client\n";
                        continue;
                    }
                    // Encrypted payload starts AFTER header
                    int enc_len = n - sizeof(PacketHeader);
                    char *enc_payload = (char *)(buf + sizeof(PacketHeader));

                    // Decrypt payload
                    enc.decrypt(enc_payload, enc_len, temp, client->xor_key);

                    // Basic sanity: ensure we have at least IPv4 header size in decrypted packet
                    if (enc_len < 20)
                    {
                        std::cout << "[WARN] decrypted packet too small (" << enc_len << " bytes) - skipping\n";
                        continue;
                    }

                    // uint8_t ver_ihl = (uint8_t)temp[0];
                    // uint8_t version = ver_ihl >> 4;
                    // uint8_t ihl = ver_ihl & 0x0F;
                    // uint8_t proto = (uint8_t)temp[9];
                    // in_addr src_a;
                    // memcpy(&src_a.s_addr, temp + 12, 4);
                    // in_addr dst_a;
                    // memcpy(&dst_a.s_addr, temp + 16, 4);
                    // char s_src[64] = {0}, s_dst[64] = {0};
                    // inet_ntop(AF_INET, &src_a, s_src, sizeof(s_src));
                    // inet_ntop(AF_INET, &dst_a, s_dst, sizeof(s_dst));

                    // std::cout << "[DEBUG] Decrypted packet: ver=" << unsigned(version)
                    //           << " ihl=" << unsigned(ihl) << " proto=" << unsigned(proto)
                    //           << " src=" << s_src << " dst=" << s_dst << " len=" << enc_len << "\n";
                    // uint32_t src_host = ntohl(src_a.s_addr);

                    write(tun, temp, enc_len);
                    std::cout << "[UDP→TUN] Wrote " << enc_len << " bytes to TUN\n";
                }
                else
                {

                    std::cout << "[INFO] Non-DATA packet received, type="
                              << int(hdr->type) << " (ignored for now)\n";
                    continue;
                }
            }
        }

        if (FD_ISSET(tun, &rf))
        {
            int n = read(tun, buf, sizeof(buf));
            if (n > 0)
            {

                uint8_t proto = (uint8_t)buf[9];

                in_addr src_a, dst_a;
                memcpy(&src_a.s_addr, buf + 12, 4);
                memcpy(&dst_a.s_addr, buf + 16, 4);
                char s_src[64], s_dst[64];
                inet_ntop(AF_INET, &src_a, s_src, sizeof(s_src));
                inet_ntop(AF_INET, &dst_a, s_dst, sizeof(s_dst));

                std::cout << "[TUN-IN] IPv4 packet: proto=" << unsigned(proto)
                          << " src=" << s_src << " dst=" << s_dst
                          << " len=" << n << "\n";

                uint32_t dst_host = ntohl(dst_a.s_addr);
                target = cm.getClientByServerIp(dst_host);
                if (!target)
                {
                    std::cout << "[TUN-IN] Unknown VPN destination IP: " << dst_host
                              << " (" << s_dst << "), cannot forward\n";
                    continue;
                }
                std::cout << "[TUN→UDP] " << n << " bytes\n";
                // Encrypt data before sending UDP
                PacketHeader hdr;
                hdr.type = PKT_DATA;
                hdr.session_id = 0; // unused for now
                                    // Copy header
                memcpy(temp, &hdr, sizeof(hdr));
                // Encrypt payload AFTER header
                enc.encrypt((char *)buf, n, temp + sizeof(hdr), target->xor_key);

                // Send header + encrypted payload
                sendto(sock,
                       temp,
                       sizeof(hdr) + n,
                       0,
                       (struct sockaddr *)&target->client_udp_addr,
                       sizeof(target->client_udp_addr));
            }
        }
    }

    close(tun);
    close(sock);
    return 0;
}
