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
#include "crypto/XorCipher.h"
#include "sessions/session/ClientSession.h"
#include "protocol/Handshake.h"
int main()
{

    ClientSession client_connection_sessions;
    ClientManager cm(100, "10.8.0.2");
    int tun = TunDevice::create("tun0");
    // Example usage in your TUN/UDP loop
    XorCipher &enc = XorCipher::getInstance();
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
    const int HANDSHAKE_TIMEOUT = 10; // seconds
    while (true)
    {

        // Periodically erase expired sessions
        client_connection_sessions.eraseExpiredSessions(HANDSHAKE_TIMEOUT);
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

                    uint32_t nextAvailableIp = cm.getNextAvailableIp();
                    if (nextAvailableIp == 0) {
                        std::cout << "[ERROR] No available VPN IPs to assign\n";
                        continue;
                    }

                    uint32_t assigned_ip = nextAvailableIp;

                    WelcomePacket welcome{};
                    welcome.hdr.type = PKT_WELCOME;
                    welcome.hdr.session_id = hello->client_magic; // unused for now
                    welcome.assigned_tun_ip = htonl(assigned_ip);
                    long long random_b = randomNumGen(1000, 5000);
                    welcome.ys = htonl(modexp(G, random_b, P)); // server's public value
                    // Create SessionState for this client
                    client_connection_sessions.addSession(
                        client_addr,
                        hello->client_magic,
                        assigned_ip,
                        ntohl(hello->yc),
                        random_b);
                        
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
                    SessionState *session = client_connection_sessions.getSession(client_addr);
                    if (session == nullptr)
                    {
                        std::cout << "[WARN] CLIENT_ACK from unknown client\n";
                        continue;
                    }
                    uint32_t shared_secret = modexp(session->yc, session->b, P);
                    uint8_t xor_key = calculateXORKey(shared_secret);

                    std::cout << "[INFO] Calculated XOR key: " << unsigned(xor_key);
                    // Add client to ClientManager
                    cm.addClient(client_addr, session->assigned_tun_ip, xor_key);
                    // Delete session state as handshake is complete
                    client_connection_sessions.eraseSession(client_addr);
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
                    enc.crypt(enc_payload, enc_len, temp, client->xor_key);

                    // Basic sanity: ensure we have at least IPv4 header size in decrypted packet
                    if (enc_len < 20)
                    {
                        std::cout << "[WARN] decrypted packet too small (" << enc_len << " bytes) - skipping\n";
                        continue;
                    }


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
                enc.crypt((char *)buf, n, temp + sizeof(hdr), target->xor_key);

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
