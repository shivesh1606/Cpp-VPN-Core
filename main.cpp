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
#include "net/socket/SocketManager.h"
#include <sys/uio.h>
#include <sys/time.h>

constexpr int RX_BATCH = 8;
constexpr int RX_BUF_SIZE = 2000;
constexpr int TX_BATCH = 8;
constexpr int TX_BUF_SIZE = 2000;

void handleUdpToTun(ClientManager &cm, XorCipher &enc, int &tun,
                    unsigned char *buf, int &n,
                    struct sockaddr_in &client_addr)

{
    // Placeholder for UDP to TUN handling logic
    static char temp[2000];
    Client *client;
    // std::cout << "[INFO] DATA packet received\n";
    client = cm.getClientByUdp(client_addr);

    if (!client)
    {
        std::cout << "[WARN] DATA packet from unknown client\n";
        return;
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
        return;
    }
    ssize_t _ = write(tun, temp, enc_len);

    // std::cout << "[UDP→TUN] Wrote " << enc_len << " bytes to TUN\n";
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
            std::cout << "[WARN] Short HELLO packet\n";
            return;
        }

        HelloPacket *hello = (HelloPacket *)buf;
        //
        // std::cout << "[INFO] HELLO packet received, client_magic="
        //           << hello->client_magic << "\n";

        uint32_t nextAvailableIp = cm.getNextAvailableIp();
        if (nextAvailableIp == 0)
        {
            std::cout << "[ERROR] No available VPN IPs to assign\n";
            return;
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
            return;
        }

        // std::cout << "[INFO] CLIENT_ACK packet received\n";
        // check if session exists, etc.
        SessionState *session = client_connection_sessions.getSession(client_addr);
        if (session == nullptr)
        {
            std::cout << "[WARN] CLIENT_ACK from unknown client\n";
            return;
        }
        uint32_t shared_secret = modexp(session->yc, session->b, P);
        uint8_t xor_key = calculateXORKey(shared_secret);

        // std::cout << "[INFO] Calculated XOR key: " << unsigned(xor_key);
        // Add client to ClientManager
        cm.addClient(client_addr, session->assigned_tun_ip, xor_key);
        // Delete session state as handshake is complete
        client_connection_sessions.eraseSession(client_addr);
    }

    else
    {

        std::cout << "[INFO] Non-DATA packet received, type="
                  << int(hdr->type) << " (ignored for now)\n";
        return;
    }
}
int main()
{
    std::cout.setf(std::ios::unitbuf); // <-- flush after every output
    ClientSession client_connection_sessions;
    ClientManager cm(100, "10.8.0.2");
    int tun = TunDevice::create("tun0");
    // Example usage in your TUN/UDP loop
    XorCipher &enc = XorCipher::getInstance();
    int sock = SocketManager::createUdpSocket(5555);
    if (sock < 0)
    {
        std::cerr << "[ERROR] Failed to create UDP socket\n";
        return 1;
    }
    unsigned char main_loop_buf[2000];
    // char temp[2000];
    // struct sockaddr_in client_addr{};
    // socklen_t client_len = sizeof(client_addr);
    char client_ip[64];
    // Client *client, *target;
    const int HANDSHAKE_TIMEOUT = 10; // seconds
    fcntl(sock, F_SETFL, O_NONBLOCK);
    fcntl(tun, F_SETFL, O_NONBLOCK);

    std::cout << "Sock fd is " << sock << " and tun fd is " << tun << "\n";

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
            // Per-batch storage (stack-owned, safe)
            struct mmsghdr msgs[RX_BATCH];
            struct iovec iovecs[RX_BATCH];
            struct sockaddr_in addrs[RX_BATCH];
            unsigned char bufs[RX_BATCH][RX_BUF_SIZE];
            memset(msgs, 0, sizeof(msgs));
            memset(addrs, 0, sizeof(addrs));
            for (int i = 0; i < RX_BATCH; i++)
            {
                iovecs[i].iov_base = bufs[i];
                iovecs[i].iov_len = RX_BUF_SIZE;

                msgs[i].msg_hdr.msg_iov = &iovecs[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
                msgs[i].msg_hdr.msg_control = nullptr;
                msgs[i].msg_hdr.msg_controllen = 0;

                msgs[i].msg_hdr.msg_name = &addrs[i];
                msgs[i].msg_hdr.msg_namelen = sizeof(addrs[i]);
            }

            while (true)
            {
                int rcvd = recvmmsg(sock, msgs, RX_BATCH, 0, nullptr);

                if (rcvd > 0)
                {
                    for (int i = 0; i < rcvd; i++)
                    {

                        int n = msgs[i].msg_len;
                        unsigned char *buf = bufs[i];
                        struct sockaddr_in &client_addr = addrs[i];
                        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
                        // std::cout << "[IN] Received " << n << " bytes from " << client_ip
                        //           << ":" << ntohs(client_addr.sin_port) << "\n";
                        // std::cout << "[UDP→TUN] " << n << " bytes\n";
                        // Decrypt data after receiving UDP
                        if (n < (int)sizeof(PacketHeader))
                        {
                            std::cout << "[WARN] Packet too small for header\n";
                            continue;
                        }

                        PacketHeader *hdr = (PacketHeader *)buf;
                        if (hdr->type == PKT_DATA)
                        {
                            handleUdpToTun(cm, enc, tun, buf, n, client_addr);
                        }
                        else
                        {
                            handleHandshake(hdr, n, buf, client_addr, sock,
                                            client_connection_sessions, cm);
                        }
                    }
                }
                else
                {
                    if (errno == EWOULDBLOCK || errno == EAGAIN)
                    {
                        break; // No more data to read
                    }
                    perror("recvfrom");
                    break;
                }
                // If kernel returned fewer than batch, socket is drained
                if (rcvd < RX_BATCH)
                    break;
            }
        }
        if (FD_ISSET(tun, &rf))
        {
            struct mmsghdr msgs[TX_BATCH];
            struct iovec iovecs[TX_BATCH];
            unsigned char bufs[TX_BATCH][TX_BUF_SIZE];

            memset(msgs, 0, sizeof(msgs));
            int batch_count = 0;

            while (true)
            {
                int n = read(tun, main_loop_buf, sizeof(main_loop_buf));
                if (n < 0)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;
                    perror("read tun");
                    break;
                }

                if (n == 0)
                    break;

                // ---- ORIGINAL LOGIC, INLINE ----
                in_addr dst_a;
                memcpy(&dst_a.s_addr, main_loop_buf + 16, 4);
                uint32_t dst_host = ntohl(dst_a.s_addr);

                Client *target = cm.getClientByServerIp(dst_host);
                if (!target)
                    continue;

                PacketHeader hdr;
                hdr.type = PKT_DATA;
                hdr.session_id = 0;

                unsigned char *out = bufs[batch_count];
                memcpy(out, &hdr, sizeof(hdr));
                enc.crypt((char *)main_loop_buf, n, (char *)out + sizeof(hdr), target->xor_key);

                iovecs[batch_count].iov_base = out;
                iovecs[batch_count].iov_len = sizeof(hdr) + n;

                msgs[batch_count].msg_hdr.msg_iov = &iovecs[batch_count];
                msgs[batch_count].msg_hdr.msg_iovlen = 1;
                msgs[batch_count].msg_hdr.msg_name =
                    &target->client_udp_addr;
                msgs[batch_count].msg_hdr.msg_namelen =
                    sizeof(target->client_udp_addr);

                batch_count++;

                // ---- FLUSH CONDITIONS ----
                if (batch_count == TX_BATCH)
                {
                    int sent = sendmmsg(sock, msgs, batch_count, 0);
                    if (sent < 0)
                    {
                        perror("sendmmsg");
                        batch_count = 0;
                    }
                    else if (sent < batch_count)
                    {
                        // Drop remaining packets intentionally (UDP)
                        // Optional debug log:
                        std::cout << "[WARN] sendmmsg dropped "
                                  << (batch_count - sent) << " packets\n";
                        batch_count = 0;
                    }
                    else
                    {
                        batch_count = 0;
                    }
                }
            }
            if (batch_count > 0)
            {
                int sent = sendmmsg(sock, msgs, batch_count, 0);
                if (sent < 0)
                {
                    perror("sendmmsg");
                    batch_count = 0;
                }
                else if (sent < batch_count)
                {
                    // Drop remaining packets intentionally (UDP)
                    // Optional debug log:
                    std::cout << "[WARN] sendmmsg dropped "
                              << (batch_count - sent) << " packets\n";
                    batch_count = 0;
                }
                else
                {
                    batch_count = 0;
                }
            }
        }
    }

    close(tun);
    close(sock);
    return 0;
}
