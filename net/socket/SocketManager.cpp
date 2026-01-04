#include "SocketManager.h"

int SocketManager::createUdpSocket(uint16_t port) 
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return -1;
    }

    struct sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = INADDR_ANY;
    srv.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0)
    {
        perror("bind");
        close(sock);
        return -1;
    }

    std::cout << "[+] UDP listening on port " << port << "\n";
    return sock;
}