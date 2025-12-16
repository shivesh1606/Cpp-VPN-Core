#include "Client_Manager.h"
#include <string>

ClientManager::ClientManager(int poolSize, const char* startIp) {
    // Initialize pool of available IPs
    ipPool = std::vector<uint32_t>(poolSize, 0);

    // Convert base IP string -> uint32 host order
    baseIp = ntohl(inet_addr(startIp));
}



Client* ClientManager::addClient(const sockaddr_in &clientUdpAddr, uint32_t androidTunIp,char &xor_key) {

    bool ipInUse = isIpInUse(androidTunIp);
    if(ipInUse){
        // This should never happen since getAvailableIp marks it as used
        return nullptr;
    }


    Client newClient;
    newClient.client_udp_addr = clientUdpAddr;
    newClient.android_client_tun_ip = androidTunIp;
    newClient.xor_key = xor_key;

    // Store both mappings
    vpn_to_client[androidTunIp] = newClient;
    makeIpInUse(androidTunIp);
    return &vpn_to_client[androidTunIp];
}



Client* ClientManager::getClientByServerIp(uint32_t ip) {
    auto it = vpn_to_client.find(ip);
    return (it != vpn_to_client.end()) ? &it->second : nullptr;
}

Client* ClientManager::getClientByUdp(const sockaddr_in &addr){
    for (auto &pair : vpn_to_client) {
        const Client &client = pair.second;
        if (client.client_udp_addr.sin_addr.s_addr == addr.sin_addr.s_addr &&
            client.client_udp_addr.sin_port == addr.sin_port) {
            return &pair.second;
        }
    }
    return nullptr;
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