#ifndef TUNDEVICE_H
#define TUNDEVICE_H

#include <iostream>
#include "utils/logger.h"

class TunDevice {
public:
    // Throws on failure or returns fd
    static int create(const char* name = "tun0");
    // Constructor and Destructor with basic logging
    TunDevice(){
        LOG(LOG_INFO, "[+] TunDevice instance created\n");
    }
    ~TunDevice(){
        LOG(LOG_INFO, "[+] TunDevice instance destroyed\n");
    }
};

#endif // TUNDEVICE_H