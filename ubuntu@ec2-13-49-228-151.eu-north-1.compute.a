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

int create_tun(const char *name="tun0") {
    struct ifreq ifr{};
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("open /dev/net/tun");
        exit(1);
    }
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ-1] = 0; // ensure null termination
    if (ioctl(fd, TUNSETIFF, (void*)&ifr) < 0) {
        perror("ioctl TUNSETIFF");
        exit(1);
    }
    std::cout << "[+] TUN created: " << ifr.ifr_name << "\n";
    return fd;
}

int main() {
    int tun = create_tun("tun0");
    // Example usage in your TUN/UDP loop
    Encryption& enc = Encryption::getInstance();
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = INADDR_ANY;
    srv.sin_port = htons(5555);

    if (bind(sock, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
        perror("bind");
        return 1;
    }

    std::cout << "[+] UDP listening on 0.0.0.0:5555\n";

    unsigned char buf[2000];
    char temp[2000];
    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    bool have_client = false;

    while (true) {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(sock, &rf);
        FD_SET(tun, &rf);

        int nf = std::max(sock, tun) + 1;
        int ret = select(nf, &rf, nullptr, nullptr, nullptr);
        if (ret < 0) {
            perror("select");
            continue;
        }

        if (FD_ISSET(sock, &rf)) {
            int n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr*)&client_addr, &client_len);
            if (n > 0) {
                have_client = true;
                std::cout << "[UDP→TUN] " << n << " bytes\n";
                // Decrypt data after receiving UDP
                enc.decrypt((char*)buf, n, temp);
                write(tun, temp, n);
            }
        }

        if (have_client && FD_ISSET(tun, &rf)) {
            int n = read(tun, buf, sizeof(buf));
            if (n > 0) {
                std::cout << "[TUN→UDP] " << n << " bytes\n";
                // Encrypt data before sending UDP
                enc.encrypt((char*)buf, n, temp);
                sendto(sock, temp, n, 0, (struct sockaddr*)&client_addr, client_len);
            }
        }
    }

    close(tun);
    close(sock);
    return 0;
}
