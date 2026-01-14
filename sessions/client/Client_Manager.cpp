#include "Client_Manager.h"
#include <string>
#include <iostream>
#include "utils/logger.h"

ClientManager::ClientManager(int poolSize, const char *startIp)
{
    // Initialize pool of available IPs
    ipPool = std::vector<uint32_t>(poolSize, 0);

    // Convert base IP string -> uint32 host order
    baseIp = ntohl(inet_addr(startIp));
    LOG(LOG_INFO, "[+] ClientManager created with IP pool starting at %s", startIp);
}

ClientManager::~ClientManager()
{
    LOG(LOG_INFO, "[+] ClientManager destroyed, cleaning up %zu clients", vpn_to_client.size());
}

Client *ClientManager::addClient(const sockaddr_in &clientUdpAddr, uint32_t androidTunIp, uint8_t &xor_key, uint32_t session_id)
{

    bool ipisActive = isIpInStateActive(androidTunIp);
    if (ipisActive)
    {
        // This should never happen since getAvailableIp marks it as used
        return nullptr;
    }

    Client newClient;
    newClient.client_udp_addr = clientUdpAddr;
    newClient.android_client_tun_ip = androidTunIp;
    newClient.xor_key = xor_key;
    newClient.session_id = session_id;

    makeIpInUse(androidTunIp); // ← THIS is where IP becomes ACTIVE
    auto [it, inserted] = vpn_to_client.emplace(androidTunIp, newClient);

    if (!inserted)
    {
        LOG(LOG_ERROR, "[ERROR] IP collision when adding client (IP already in use)");
        freeIp(androidTunIp); // Rollback IP usage
        return nullptr;
    }
    session_to_vpn_ip[newClient.session_id] = androidTunIp;
    uint64_t packedAddr = packAddr(clientUdpAddr);
    udp_to_vpn_ip[packedAddr] = androidTunIp;
    return &it->second;
}

Client *ClientManager::getClientByServerIp(uint32_t ip)
{
    auto it = vpn_to_client.find(ip);
    return (it != vpn_to_client.end()) ? &it->second : nullptr;
}

Client *ClientManager::getClientByUdp(const sockaddr_in &addr)
{
    uint64_t key = packAddr(addr);
    auto it = udp_to_vpn_ip.find(key);

    if (it != udp_to_vpn_ip.end())
    {
        return &vpn_to_client[it->second];
    }
    return nullptr;
}
bool ClientManager::isIpInUse(uint32_t ip) const
{
    uint32_t index = ip - baseIp;
    if (index >= ipPool.size())
        return false;
    return ipPool[index] != IpState::FREE;
}
// Client *ClientManager::getClientByClientTunIpAndUdpAddr(const sockaddr_in &addr, uint32_t clientTunIp)
// {
//     if (!isIpInUse(clientTunIp))
//     {
//         return nullptr;
//     }
//     Client client = vpn_to_client[clientTunIp];

//     // Verify UDP address matches
//     if (client.client_udp_addr.sin_addr.s_addr != addr.sin_addr.s_addr ||
//         client.client_udp_addr.sin_port != addr.sin_port)
//     {
//         return nullptr;
//     }
//     return &vpn_to_client[clientTunIp];
// }

bool ClientManager::isIpInStateActive(uint32_t ip) const
{
    uint32_t index = ip - baseIp;
    if (index >= ipPool.size())
        return false;
    return ipPool[index] == IpState::ACTIVE;
}

bool ClientManager::makeIpInUse(uint32_t ip)
{
    uint32_t index = ip - baseIp;
    if (index >= ipPool.size())
        return false;
    ipPool[index] = IpState::ACTIVE;
    return true;
}

uint32_t ClientManager::getNextAvailableIp()
{
    for (size_t i = 0; i < ipPool.size(); ++i)
    {
        if (ipPool[i] == 0)
        {
            ipPool[i] = IpState::RESERVED; // Mark as reserved
            return baseIp + i;             // ❗ DO NOT MARK USED
        }
    }
    return 0;
}

void ClientManager::freeIp(uint32_t ip)
{
    uint32_t index = ip - baseIp;
    if (index >= ipPool.size())
    {
        LOG(LOG_WARN, "[WARN] Attempt to free out-of-bounds IP");
        return;
    }

    if (ipPool[index] == 0)
    {
        LOG(LOG_WARN, "[WARN] Attempt to free an IP that is already free");
        return;
    }

    auto it = vpn_to_client.find(ip);
    if (it != vpn_to_client.end())
    {
        session_to_vpn_ip.erase(it->second.session_id); // Clean up session mapping
        udp_to_vpn_ip.erase(packAddr(it->second.client_udp_addr)); // Clean up BEFORE erasing 'it'
        vpn_to_client.erase(it);
    }


    ipPool[index] = IpState::FREE;
}

uint32_t ClientManager::generateSessionId()
{
    // In a real system, you'd check for collisions or reuse old IDs
    return nextSessionId++;
}

Client *ClientManager::getClientBySessionId(uint32_t session_id)
{
    auto it = session_to_vpn_ip.find(session_id);
    if (it == session_to_vpn_ip.end())
        return nullptr;

    uint32_t vpn_ip = it->second;
    return &vpn_to_client[vpn_ip];
}

void ClientManager::updateClientEndpoint(uint32_t session_id, const sockaddr_in &newAddr)
{
    Client *client = getClientBySessionId(session_id);
    if (client)
    {
        // 1. Capture the OLD key before changing anything
        uint64_t oldPackedAddr = packAddr(client->client_udp_addr);
        char oldIp[INET_ADDRSTRLEN], newIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client->client_udp_addr.sin_addr, oldIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &newAddr.sin_addr, newIp, INET_ADDRSTRLEN);

        LOG(LOG_INFO, "[ROAMING] Session %u moved from %s:%d to %s:%d",
            session_id, oldIp, ntohs(client->client_udp_addr.sin_port),
            newIp, ntohs(newAddr.sin_port));

        client->client_udp_addr = newAddr;
        // Update the UDP address mapping
        udp_to_vpn_ip.erase(oldPackedAddr);
        uint64_t newPackedAddr = packAddr(newAddr);
        udp_to_vpn_ip[newPackedAddr] = client->android_client_tun_ip;

    }
}