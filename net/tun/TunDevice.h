#ifndef TUNDEVICE_H
#define TUNDEVICE_H

#include <cstdint>
#include <iostream>
#include <string>
#include "utils/logger.h"

class TunDevice {
public:
    // Throws on failure or returns fd
    static int create(const char* name = "tun0");

    // Sets the interface address/netmask and MTU and brings the link up (plan N5), like
    // `ip addr add A/P dev NAME && ip link set NAME mtu M up`. Needs CAP_NET_ADMIN.
    // `addr` is host byte order. Returns false and sets `error` on failure.
    static bool configure(const char* name, uint32_t addr, int prefix, int mtu, std::string& error);

    // Constructor and Destructor with basic logging
    TunDevice(){
        LOG(LOG_INFO, "[+] TunDevice instance created\n");
    }
    ~TunDevice(){
        LOG(LOG_INFO, "[+] TunDevice instance destroyed\n");
    }
};

#endif // TUNDEVICE_H
