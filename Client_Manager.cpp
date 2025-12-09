#include "Client_Manager.h"
#include <string>

ClientManager::ClientManager(int poolSize, const char* startIp) {
    // Initialize pool of available IPs
    ipPool = std::vector<uint32_t>(poolSize, 0);

    // Convert base IP string -> uint32 host order
    baseIp = ntohl(inet_addr(startIp));
}



Client* ClientManager::addClient(const sockaddr_in &clientUdpAddr, uint32_t androidTunIp) {

    bool ipInUse = isIpInUse(androidTunIp);
    if(ipInUse){
        // This should never happen since getAvailableIp marks it as used
        return nullptr;
    }


    Client newClient;
    newClient.client_udp_addr = clientUdpAddr;
    newClient.android_client_tun_ip = androidTunIp;

    // Store both mappings
    vpn_to_client[androidTunIp] = newClient;
    makeIpInUse(androidTunIp);
    return &vpn_to_client[androidTunIp];
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

Client* ClientManager::getClientByClientTunIpAndUdpAddr(const sockaddr_in &addr,uint32_t clientTunIp) {
    if(!isIpInUse(clientTunIp)){
        return nullptr;
    }
    Client client = vpn_to_client[clientTunIp];

    // Verify UDP address matches
    if(client.client_udp_addr.sin_addr.s_addr != addr.sin_addr.s_addr ||
       client.client_udp_addr.sin_port != addr.sin_port) {
        return nullptr;
    }
    makeIpInUse(clientTunIp);
    return &vpn_to_client[clientTunIp];
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

bool ClientManager::isIpInUse(uint32_t ip) const{
    uint32_t index = ip - baseIp;
    if (index >= ipPool.size()) return false;
    return ipPool[index] == 1;
}

bool ClientManager::makeIpInUse(uint32_t ip){
    uint32_t index = ip - baseIp;
    if (index >= ipPool.size()) return false;
    ipPool[index] = 1;
    return true;
}