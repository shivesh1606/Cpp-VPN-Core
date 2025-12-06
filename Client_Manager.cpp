#include "Client_Manager.h"
#include <string>

ClientManager::ClientManager(int poolSize, const char* startIp) {
    // Initialize pool of available IPs
    ipPool = std::vector<uint32_t>(poolSize, 0);

    // Convert base IP string -> uint32 host order
    baseIp = ntohl(inet_addr(startIp));
}



uint32_t ClientManager::addClient(const sockaddr_in &clientUdpAddr, uint32_t androidTunIp) {

    uint32_t serverAssignedIp = getAvailableIp();
    if (serverAssignedIp == 0) {
        return 0; // No free IP
    }

    Client newClient;
    newClient.client_udp_addr = clientUdpAddr;
    newClient.android_client_tun_ip = androidTunIp;

    // Store both mappings
    vpn_to_client[serverAssignedIp] = newClient;
    udp_to_vpn[addrToKey(clientUdpAddr)] = serverAssignedIp;

    return serverAssignedIp;
}

void ClientManager::removeClient(uint32_t serverAssignedIp) {
    auto it = vpn_to_client.find(serverAssignedIp);
    if (it == vpn_to_client.end()) return;

    // Remove reverse mapping
    std::string key = addrToKey(it->second.client_udp_addr);
    udp_to_vpn.erase(key);

    // Remove client
    vpn_to_client.erase(it);

    // Free IP back in pool
    uint32_t index = serverAssignedIp - baseIp;
    if (index < ipPool.size()) {
        ipPool[index] = 0;
    }
}

Client* ClientManager::getClientByServerIp(uint32_t ip) {
    auto it = vpn_to_client.find(ip);
    return (it != vpn_to_client.end()) ? &it->second : nullptr;
}

Client* ClientManager::getClientByUdp(const sockaddr_in &addr) {
    std::string key = addrToKey(addr);
    auto it = udp_to_vpn.find(key);
    if (it == udp_to_vpn.end()) return nullptr;

    return getClientByServerIp(it->second);
}

std::string ClientManager::addrToKey(const sockaddr_in &addr) const {
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), ipStr, INET_ADDRSTRLEN);
    uint16_t port = ntohs(addr.sin_port);
    return std::string(ipStr) + ":" + std::to_string(port);
}

uint32_t ClientManager::getAvailableIp() {
    for (size_t i = 0; i < ipPool.size(); ++i) {
        if (ipPool[i] == 0) {
            ipPool[i] = 1; // mark used
            return baseIp + i;
        }
    }
    return 0; // No IP available
}
