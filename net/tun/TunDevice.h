#ifndef TUNDEVICE_H
#define TUNDEVICE_H

#include <iostream>

class TunDevice {
public:
    // Throws on failure or returns fd
    static int create(const char* name = "tun0");
    // Constructor and Destructor with basic logging
    TunDevice(){
        std::cout << "[+] TunDevice instance created\n";
    }
    ~TunDevice(){
        std::cout << "[-] TunDevice instance destroyed\n";
    }
};

#endif // TUNDEVICE_H