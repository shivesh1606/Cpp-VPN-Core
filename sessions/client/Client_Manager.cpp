#include "Client_Manager.h"
#include <string>
#include <iostream>
#include "utils/logger.h"

ClientManager::ClientManager(int poolSize, const char* startIp) {
    // Initialize pool of available IPs
    ipPool = std::vector<uint32_t>(poolSize, 0);

    // Convert base IP string -> uint32 host order
    baseIp = ntohl(inet_addr(startIp));
    LOG(LOG_INFO, "[+] ClientManager created with IP pool starting at %s", startIp);
}

ClientManager::~ClientManager() {
    LOG(LOG_INFO, "[+] ClientManager destroyed, cleaning up %zu clients", vpn_to_client.size());
}

Client* ClientManager::addClient(const sockaddr_in &clientUdpAddr, uint32_t androidTunIp,uint8_t &xor_key) {

    bool ipisActive = isIpInStateActive(androidTunIp);
    if(ipisActive){
        // This should never happen since getAvailableIp marks it as used
        return nullptr;
    }

    
    Client newClient;
    newClient.client_udp_addr = clientUdpAddr;
    newClient.android_client_tun_ip = androidTunIp;
    newClient.xor_key = xor_key;


    
    makeIpInUse(androidTunIp);  // ← THIS is where IP becomes ACTIVE
    auto [it, inserted] = vpn_to_client.emplace(androidTunIp, newClient);
    return &it->second;

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
bool ClientManager::isIpInUse(uint32_t ip) const {
    uint32_t index = ip - baseIp;
    if (index >= ipPool.size()) return false;
    return ipPool[index] != IpState::FREE;
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
    return &vpn_to_client[clientTunIp];
}




bool ClientManager::isIpInStateActive(uint32_t ip) const {
    uint32_t index = ip - baseIp;
    if (index >= ipPool.size()) return false;
    return ipPool[index] == IpState::ACTIVE;
}


bool ClientManager::makeIpInUse(uint32_t ip){
    uint32_t index = ip - baseIp;
    if (index >= ipPool.size()) return false;
    ipPool[index]= IpState::ACTIVE;
    return true;
}

uint32_t ClientManager::getNextAvailableIp(){
    for (size_t i = 0; i < ipPool.size(); ++i) {
        if (ipPool[i] == 0) {
            ipPool[i] = IpState::RESERVED; // Mark as reserved
            return baseIp + i; // ❗ DO NOT MARK USED
        }
    }
    return 0;
}


void ClientManager::freeIp(uint32_t ip) {
    uint32_t index = ip - baseIp;
    if (index >= ipPool.size()) {
        LOG(LOG_WARN, "[WARN] Attempt to free out-of-bounds IP");
        return;
    }

    if (ipPool[index] == 0) {
        LOG(LOG_WARN, "[WARN] Attempt to free an IP that is already free");
        return;
    }

    ipPool[index] = IpState::FREE;
    vpn_to_client.erase(ip);
}
