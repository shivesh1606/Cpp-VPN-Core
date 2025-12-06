#include <iostream>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <algorithm>
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
// `ihl_bytes` will be computed from pkt[0] (IHL field).
static void ipv4_recompute_checksum(uint8_t *pkt)
{
    // IHL: low 4 bits of first byte, in 32-bit words
    uint8_t ihl = pkt[0] & 0x0F;
    if (ihl < 5)
        return; // invalid, but skip

    int header_words = ihl * 2; // number of 16-bit words in header

    // Clear checksum (bytes 10-11)
    pkt[10] = 0;
    pkt[11] = 0;

    uint32_t sum = 0;
    uint16_t *words = (uint16_t *)pkt;
    for (int i = 0; i < header_words; ++i)
    {
        sum += ntohs(words[i]); // convert each 16-bit word to host order before summing
    }

    // fold 32-bit sum to 16 bits
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t checksum = (uint16_t)(~sum & 0xFFFF);

    words[5] = htons(checksum); // checksum is the 6th 16-bit word (offset 10 bytes)
}

int main()
{
    int tun = create_tun("tun0");
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = INADDR_ANY;
    srv.sin_port = htons(5555);
    bind(sock, (struct sockaddr *)&srv, sizeof(srv));

    Encryption &enc = Encryption::getInstance();

    // ------------------------------
    // Create Client Manager
    // ------------------------------
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
        select(nf, &rf, nullptr, nullptr, nullptr);

        // ============================
        // UDP → TUN (client → internet)
        // ============================
        if (FD_ISSET(sock, &rf))
        {
            int n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&udp_addr, &addr_len);

            if (n > 0)
            {
                // 1) decrypt into temp
                enc.decrypt((char *)buf, n, temp);

                // 2) identify / add client
                Client *client = cm.getClientByUdp(udp_addr);
                uint32_t assigned_ip;
                if (!client)
                {
                    assigned_ip = cm.addClient(udp_addr, inet_addr("10.8.0.2")); // store android tun ip in network order
                    if (assigned_ip == 0)
                    {
                        std::cerr << "[!] IP pool exhausted!" << std::endl;
                        continue;
                    }
                    client = cm.getClientByUdp(udp_addr);
                }
                else
                {
                    assigned_ip = cm.getServerAssignedIp(udp_addr); // returns host-order vpn ip
                }

                // 3) write server-assigned VPN IP into decrypted packet (network order)
                uint32_t vpn_net = htonl(assigned_ip);
                memcpy(temp + 12, &vpn_net, 4); // IPv4 src offset = 12

                // 4) recompute IPv4 header checksum (handles IHL)
                ipv4_recompute_checksum((uint8_t *)temp);

                // 5) forward into tun
                ssize_t w = write(tun, temp, n);
                if (w < 0)
                    perror("write(tun)");
            }
        }

        // ============================
        // TUN → UDP
        // ============================
        if (FD_ISSET(tun, &rf))
        {
            int n = read(tun, buf, sizeof(buf));
            if (n > 0)
            {
                // extract dest IP (network order in buffer)
                uint32_t dst_net;
                memcpy(&dst_net, buf + 16, 4);
                uint32_t dst_host = ntohl(dst_net);

                Client *target = cm.getClientByServerIp(dst_host); // expects host order
                if (!target)
                {
                    std::cout << "[!] Unknown VPN destination IP: " << dst_host << "\n";
                    continue;
                }

                // overwrite destination with client's Android TUN IP (already stored in network order)
                uint32_t android_ip_net = target->android_client_tun_ip;
                memcpy(buf + 16, &android_ip_net, 4);

                // recompute IPv4 checksum on buf (before encryption)
                ipv4_recompute_checksum((uint8_t *)buf);

                // encrypt buf -> temp
                enc.encrypt((char *)buf, n, temp);

                // send to client UDP addr
                ssize_t s = sendto(sock, temp, n, 0,
                                   (struct sockaddr *)&target->client_udp_addr,
                                   sizeof(target->client_udp_addr));
                if (s < 0)
                    perror("sendto");
            }
        }
    }
}
