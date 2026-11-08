#include "TunDevice.h"

#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <cstring>
#include <stdexcept>
#include <cerrno>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

int TunDevice::create(const char* name)
{
    struct ifreq ifr{};
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        throw std::runtime_error("Failed to open /dev/net/tun");
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        throw std::runtime_error("ioctl(TUNSETIFF) failed");
    }

    LOG(LOG_INFO, "TUN device %s created with fd %d", ifr.ifr_name, fd);
    return fd;
}

bool TunDevice::configure(const char* name, uint32_t addr, int prefix, int mtu, std::string& error)
{
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) {
        error = std::string("socket: ") + std::strerror(errno);
        return false;
    }
    auto request = [&](unsigned long req, ifreq& ifr, const char* what) {
        if (ioctl(s, req, &ifr) == 0)
            return true;
        error = std::string(what) + " on " + name + ": " + std::strerror(errno);
        return false;
    };
    auto withAddr = [&](uint32_t host) {
        ifreq ifr{};
        std::strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
        sockaddr_in sin{};
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(host);
        std::memcpy(&ifr.ifr_addr, &sin, sizeof(sin));
        return ifr;
    };

    const uint32_t mask = prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix);
    ifreq a = withAddr(addr), m = withAddr(mask), f{};
    bool ok = request(SIOCSIFADDR, a, "SIOCSIFADDR") && request(SIOCSIFNETMASK, m, "SIOCSIFNETMASK");
    if (ok) {
        ifreq u{};
        std::strncpy(u.ifr_name, name, IFNAMSIZ - 1);
        u.ifr_mtu = mtu;
        ok = request(SIOCSIFMTU, u, "SIOCSIFMTU");
    }
    if (ok) {
        std::strncpy(f.ifr_name, name, IFNAMSIZ - 1);
        ok = request(SIOCGIFFLAGS, f, "SIOCGIFFLAGS");
        f.ifr_flags |= IFF_UP | IFF_RUNNING;
        ok = ok && request(SIOCSIFFLAGS, f, "SIOCSIFFLAGS");
    }
    close(s);
    if (ok) {
        char buf[INET_ADDRSTRLEN];
        in_addr ia{};
        ia.s_addr = htonl(addr);
        inet_ntop(AF_INET, &ia, buf, sizeof(buf));
        LOG(LOG_INFO, "TUN %s configured: %s/%d mtu %d, up", name, buf, prefix, mtu);
    }
    return ok;
}
