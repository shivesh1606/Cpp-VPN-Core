#ifndef SOCKETMANAGER_H
#define SOCKETMANAGER_H
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include "utils/logger.h"
class SocketManager {
public:
    SocketManager(){
        LOG(LOG_INFO, "[+] SocketManager instance created\n");
    }
    ~SocketManager(){
        LOG(LOG_INFO, "[+] SocketManager instance destroyed\n");
    }
    static int createUdpSocket(uint16_t port) ;
};
#endif // SOCKETMANAGER_H