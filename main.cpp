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
constexpr int TX_BATCH = 8;
constexpr int TX_BUF_SIZE = 2000;

void handleUdpToTun(ClientManager &cm, XorCipher &enc, int &tun,
                    unsigned char *buf, int &n,
                    struct sockaddr_in &client_addr)

{
    // Placeholder for UDP to TUN handling logic
    static char temp[2000];
    Client *client;
    PROFILE_SCOPE_START(lookup_t0);
    client = cm.getClientByUdp(client_addr);
    PROFILE_SCOPE_END(lookup_t0, global_stats.lookup_cycles);
    if (!client)
    {
        LOG(LOG_WARN, "DATA packet from unknown client");
        global_stats.udp_rx_drops++;
        return;
    }
    // Encrypted payload starts AFTER header
    int enc_len = n - sizeof(PacketHeader);
    char *enc_payload = (char *)(buf + sizeof(PacketHeader));
    // Decrypt payload
    PROFILE_SCOPE_START(dec_t0);
    enc.crypt(enc_payload, enc_len, temp, client->xor_key);
    PROFILE_SCOPE_END(dec_t0, global_stats.dec_cycles);
    // Basic sanity: ensure we have at least IPv4 header size in decrypted packet
    if (enc_len < 20)
    {
        LOG(LOG_WARN, "Decrypted packet too small (%d bytes) - skipping", enc_len);
        return;
    }
    PROFILE_SCOPE_START(tun_wr_t0);
    ssize_t write_count = write(tun, temp, enc_len);
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
        //

        uint32_t nextAvailableIp = cm.getNextAvailableIp();
        if (nextAvailableIp == 0)
        {
            LOG(LOG_ERROR, "No available IPs to assign to new client");
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
        char client_ip_str[INET_ADDRSTRLEN];
        char assigned_ip_str[INET_ADDRSTRLEN];

        // Use inet_ntop to avoid the static buffer overlap bug of inet_ntoa
        struct in_addr net_addr;
        net_addr.s_addr = welcome.assigned_tun_ip;

        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &net_addr, assigned_ip_str, INET_ADDRSTRLEN);

        LOG(LOG_INFO, "Handshake: Client %s -> Assigned Virtual IP %s",
            client_ip_str,
            assigned_ip_str);
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

        // Add client to ClientManager
        cm.addClient(client_addr, session->assigned_tun_ip, xor_key);
        // Delete session state as handshake is complete
        client_connection_sessions.eraseSession(client_addr);
    }

    else
    {
        LOG(LOG_WARN, "Unknown handshake packet type: %d", hdr->type);
        STAT_ADD(global_stats.handshake_failures, 1);
        return;
    }
}
int main()
{
    log_init();

    struct sigaction sa{};
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // IMPORTANT: no SA_RESTART
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    ClientSession client_connection_sessions;
    ClientManager cm(100, "10.8.0.2");
    int tun = TunDevice::create("tun0");
    XorCipher &enc = XorCipher::getInstance();
    int sock = SocketManager::createUdpSocket(5555);
    if (sock < 0)
    {
        std::cerr << "[ERROR] Failed to create UDP socket\n";
        return 1;
    }
    unsigned char main_loop_buf[2000];
    const int HANDSHAKE_TIMEOUT = 10; // seconds
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

            global_stats.print_Stats();
            global_stats.reset_Stats();

            client_connection_sessions.eraseExpiredSessions(HANDSHAKE_TIMEOUT);
        }

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
                            handleUdpToTun(cm, enc, tun, buf, n, client_addr);
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

                unsigned char *out = tx_bufs[batch_count];
                memcpy(out, &hdr, sizeof(hdr));
                PROFILE_SCOPE_START(enc_t0);
                enc.crypt((char *)main_loop_buf, n, (char *)out + sizeof(hdr), target->xor_key);
                PROFILE_SCOPE_END(enc_t0, global_stats.enc_cycles);
                tx_iovecs[batch_count].iov_base = out;
                tx_iovecs[batch_count].iov_len = sizeof(hdr) + n;

                tx_msgs[batch_count].msg_hdr.msg_iov = &tx_iovecs[batch_count];
                tx_msgs[batch_count].msg_hdr.msg_iovlen = 1;
                // client addr ip+port
                tx_msgs[batch_count].msg_hdr.msg_name =
                    &target->client_udp_addr;
                tx_msgs[batch_count].msg_hdr.msg_namelen =
                    sizeof(target->client_udp_addr);

                batch_count++;
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
