#ifndef SOCKETMANAGER_H
#define SOCKETMANAGER_H
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <iostream>

class SocketManager {
public:
    SocketManager(){
        std::cout << "[+] SocketManager instance created\n";
    }
    ~SocketManager(){
        std::cout << "[-] SocketManager instance destroyed\n";
    }
    static int createUdpSocket(uint16_t port) ;
};
#endif // SOCKETMANAGER_H