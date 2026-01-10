#include "TunDevice.h"

#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <cstring>
#include <stdexcept>

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
