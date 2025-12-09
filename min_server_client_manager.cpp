#include <iostream>
#include <iomanip>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <algorithm>
#include <cstdint>
#include "Encryption.h"
#include "Client_Manager.h"

// =========================
// Create TUN Interface
// =========================
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

// Compute IPv4 header checksum in-place on buffer `pkt` (pkt points to start of IP header)
static void ipv4_recompute_checksum(uint8_t *pkt)
{
    // Need at least 20 bytes for IPv4 header
    if (!pkt)
        return;
    uint8_t ihl = pkt[0] & 0x0F;
    if (ihl < 5)
        return; // invalid header length

    int header_words = ihl * 2; // number of 16-bit words in header

    // Clear checksum (bytes 10-11)
    pkt[10] = 0;
    pkt[11] = 0;

    uint32_t sum = 0;
    uint16_t *words = (uint16_t *)pkt;
    for (int i = 0; i < header_words; ++i)
    {
        // read in network order, convert to host for sum
        sum += ntohs(words[i]);
    }

    // fold 32-bit sum to 16 bits
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t checksum = (uint16_t)(~sum & 0xFFFF);

    words[5] = htons(checksum); // checksum is the 6th 16-bit word (offset 10 bytes)
}

// small hex preview for debugging (prints up to first 16 bytes)
static void hex_preview(const unsigned char *data, int len)
{
    int to_print = std::min(len, 16);
    std::cout << std::hex << std::setfill('0');
    for (int i = 0; i < to_print; ++i)
    {
        std::cout << std::setw(2) << (int)data[i] << (i + 1 == to_print ? "" : " ");
    }
    std::cout << std::dec << std::setfill(' ') << "\n";
}

int main()
{
    int tun = create_tun("tun0");

    // IMPORTANT: configure tun0 here (server is owner of interface)
    system("ip addr add 10.8.0.1/24 dev tun0");
    system("ip link set tun0 up");
    system("ip link set tun0 mtu 1200");
    std::cout << "[+] tun0 configured with 10.8.0.1/24\n";

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
        close(sock);
        return 1;
    }

    Encryption &enc = Encryption::getInstance();
    ClientManager cm(100, "10.8.0.10");

    unsigned char buf[2000];
    char temp[2000];

    struct sockaddr_in udp_addr{};
    socklen_t addr_len = sizeof(udp_addr);

    while (true)
    {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(sock, &rf);
        FD_SET(tun, &rf);

        int nf = std::max(sock, tun) + 1;
        int sel = select(nf, &rf, nullptr, nullptr, nullptr);
        if (sel < 0)
        {
            perror("select");
            continue;
        }
        std::cout << "[DEBUG] select() -> " << sel << " (sock=" << sock << ", tun=" << tun << ")\n";

        // ============================
        // UDP → TUN (client → server)
        // ============================
        if (FD_ISSET(sock, &rf))
        {
            int n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&udp_addr, &addr_len);

            if (n > 0)
            {
                char client_ip[64];
                inet_ntop(AF_INET, &udp_addr.sin_addr, client_ip, sizeof(client_ip));
                std::cout << "[IN] Received " << n << " bytes from " << client_ip
                          << ":" << ntohs(udp_addr.sin_port) << "\n";

                // decrypt into temp
                enc.decrypt((char *)buf, n, temp);

                Client *client = cm.getClientByUdp(udp_addr);
                uint32_t assigned_ip;
                if (!client)
                {
                    assigned_ip = cm.addClient(udp_addr, inet_addr("10.8.0.2"));
                    if (assigned_ip == 0)
                    {
                        std::cerr << "[!] IP pool exhausted!" << std::endl;
                        continue;
                    }
                    // print assigned IP in dotted form
                    in_addr a;
                    a.s_addr = htonl(assigned_ip);
                    char s_assigned[64];
                    inet_ntop(AF_INET, &a, s_assigned, sizeof(s_assigned));
                    std::cout << "[CLIENT] New client assigned VPN IP: " << assigned_ip
                              << " (" << s_assigned << ")\n";
                    client = cm.getClientByUdp(udp_addr);
                }
                else
                {
                    assigned_ip = cm.getServerAssignedIp(udp_addr);
                    in_addr a;
                    a.s_addr = htonl(assigned_ip);
                    char s_assigned[64];
                    inet_ntop(AF_INET, &a, s_assigned, sizeof(s_assigned));
                    std::cout << "[CLIENT] Existing client VPN IP: " << assigned_ip
                              << " (" << s_assigned << ")\n";
                }

                // Basic sanity: ensure we have at least IPv4 header size in decrypted packet
                if (n < 20)
                {
                    std::cout << "[WARN] decrypted packet too small (" << n << " bytes) - skipping\n";
                    continue;
                }

                uint8_t ver_ihl = (uint8_t)temp[0];
                uint8_t version = ver_ihl >> 4;
                uint8_t ihl = ver_ihl & 0x0F;

                if (version != 4)
                {
                    std::cout << "[WARN] Decrypted packet is not IPv4 (ver=" << unsigned(version) << ") - skipping\n";
                    continue;
                }

                uint8_t proto = (uint8_t)temp[9];

                in_addr src_a;
                memcpy(&src_a.s_addr, temp + 12, 4);
                in_addr dst_a;
                memcpy(&dst_a.s_addr, temp + 16, 4);
                char s_src[64] = {0}, s_dst[64] = {0};
                inet_ntop(AF_INET, &src_a, s_src, sizeof(s_src));
                inet_ntop(AF_INET, &dst_a, s_dst, sizeof(s_dst));

                std::cout << "[DEBUG] Decrypted packet: ver=" << unsigned(version)
                          << " ihl=" << unsigned(ihl) << " proto=" << unsigned(proto)
                          << " src=" << s_src << " dst=" << s_dst << " len=" << n << "\n";

                // 3) write server-assigned VPN IP into decrypted packet (network order)
                uint32_t vpn_net = htonl(assigned_ip);
                memcpy(temp + 12, &vpn_net, 4);

                // 4) recompute IPv4 header checksum (handles IHL)
                ipv4_recompute_checksum((uint8_t *)temp);

                // debug print header after rewrite
                in_addr src_after;
                memcpy(&src_after.s_addr, temp + 12, 4);
                char s_src_after[64];
                inet_ntop(AF_INET, &src_after, s_src_after, sizeof(s_src_after));
                std::cout << "[DEBUG] After rewrite src=" << s_src_after << "\n";

                // 5) forward into tun (use the original decrypted length n)
                ssize_t w = write(tun, temp, n);
                if (w < 0)
                    perror("write(tun)");
                else
                    std::cout << "[TUN] Forwarded " << w << " bytes to TUN\n";
            }
        }

        // ============================
        // TUN → UDP (server → client)
        // ============================
        if (FD_ISSET(tun, &rf))
        {
            int n = read(tun, buf, sizeof(buf));
            if (n <= 0)
            {
                if (n < 0)
                    perror("[TUN-IN] read(tun) error");
                else
                    std::cout << "[TUN-IN] read(tun) returned 0 bytes\n";
                continue;
            }

            std::cout << "[TUN-IN] Read " << n << " bytes from TUN\n";
            hex_preview((unsigned char *)buf, std::min(n, 32)); // preview first 32 bytes

            uint8_t ver_ihl = (uint8_t)buf[0];
            uint8_t version = ver_ihl >> 4;

            if (version != 4)
            {
                std::cout << "[TUN-IN] Not IPv4, skipping (ver=" << unsigned(version) << ")\n";
                continue;
            }

            if (n < 20)
            {
                std::cout << "[TUN-IN] Packet too small (" << n << " bytes), skipping\n";
                continue;
            }

            uint8_t ihl = ver_ihl & 0x0F;
            uint8_t proto = (uint8_t)buf[9];
            int header_len_bytes = ihl * 4;
            if (header_len_bytes < 20 || header_len_bytes > n)
            {
                std::cout << "[TUN-IN] Invalid IHL (" << unsigned(ihl) << "), skipping\n";
                continue;
            }

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
            Client *target = cm.getClientByServerIp(dst_host);
            if (!target)
            {
                std::cout << "[TUN-IN] Unknown VPN destination IP: " << dst_host
                          << " (" << s_dst << "), cannot forward\n";
                continue;
            }

            // show client mapping
            char mapped_ip[64];
            inet_ntop(AF_INET, &target->client_udp_addr.sin_addr, mapped_ip, sizeof(mapped_ip));
            std::cout << "[TUN-IN] Mapping found: VPN dst " << dst_host
                      << " -> client UDP " << mapped_ip
                      << ":" << ntohs(target->client_udp_addr.sin_port) << "\n";

            // rewrite destination to Android client VPN IP
            uint32_t android_ip_net = target->android_client_tun_ip;
            memcpy(buf + 16, &android_ip_net, 4);

            ipv4_recompute_checksum((uint8_t *)buf);

            // encrypt and send
            enc.encrypt((char *)buf, n, temp);

            ssize_t s = sendto(sock, temp, n, 0,
                               (struct sockaddr *)&target->client_udp_addr,
                               sizeof(target->client_udp_addr));
            if (s < 0)
            {
                perror("[TUN-IN] sendto failed");
            }
            else
            {
                std::cout << "[TUN-OUT] Sent " << s << " bytes to "
                          << mapped_ip << ":" << ntohs(target->client_udp_addr.sin_port)
                          << " (rewritten dst=" << inet_ntoa(dst_a) << ")\n";
            }
        }
        }

        // cleanup (unreachable in current loop, but kept for completeness)
        close(sock);
        close(tun);
        return 0;
    
}