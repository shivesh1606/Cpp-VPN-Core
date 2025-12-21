#pragma once
#include <netinet/in.h>
#include <unordered_map>
#include <string>
#include <vector>
#include <arpa/inet.h>

/**
 * @brief Represents a connected VPN client.
 *
 * This struct links:
 *   - client_udp_addr           Real-world public IP + UDP port of client
 *   - android_client_tun_ip     The IP inside the client's TUN interface
 *
 * Note:
 *   Your Android client always uses the same TUN IP (e.g., 10.8.0.2).
 *   The server assigns a separate internal VPN IP for routing (10.8.0.x).
 */
struct Client {
    sockaddr_in client_udp_addr;     ///< Actual (public) UDP address of client
    uint32_t android_client_tun_ip;  ///< Fixed IP inside Android TUN (10.8.0.2)
    uint8_t xor_key;                  ///< Simple XOR key for this client
};

enum IpState {
    FREE = 0,
    RESERVED = 1,
    ACTIVE = 2
};
/**
 * @brief Manages all connected VPN clients and their virtual IPs.
 *
 * This class is responsible for:
 * --------------------------------
 * 1) Assigning internal VPN IPs to clients (10.8.0.x range)
 * 2) Tracking which UDP address belongs to which VPN IP
 * 3) Fast lookup:
 *      - UDP -> Client (for packets coming from real world)
 *      - VPN IP -> Client (for packets coming from TUN interface)
 *
 * Internal structures:
 * --------------------------------
 * vpn_to_client:
 *      serverAssignedVpnIp → Client
 *
 * udp_to_vpn:
 *      "ip:port" → serverAssignedVpnIp
 *
 * ipPool:
 *      A simple vector marking IPs as used/free.
 *
 */
class ClientManager {

private:
    /**
     * @brief Maps assigned VPN IPs to their Client objects.
     *
     * Key:   server-assigned VPN IP (uint32_t host order)
     * Value: Client struct containing UDP address + Android TUN IP
     *
     * Used when routing packets from server TUN → client UDP.
     */
    std::unordered_map<uint32_t, Client> vpn_to_client;

    /**
     * @brief IP allocation pool.
     *
     * ipPool[i] = 0 → free
     * ipPool[i] = 1 → in use
     *
     * Actual IP = baseIp + i
     */
    std::vector<uint32_t> ipPool;

    /**
     * @brief Starting IP for allocation.
     *
     * Example:
     *     baseIp = ntohl(inet_addr("10.8.0.10"))
     * Then the pool allocates:
     *     10.8.0.10, 10.8.0.11, 10.8.0.12, ...
     */
    uint32_t baseIp;


public:

    /**
     * @brief Constructor for ClientManager.
     *
     * @param poolSize  Number of usable internal VPN IPs
     * @param startIp   String representing first assignable IP
     *                  (e.g., "10.8.0.10")
     *
     * Example:
     *     ClientManager cm(50, "10.8.0.10");
     * Creates pool:
     *     10.8.0.10 → 10.8.0.59
     */
    ClientManager(int poolSize, const char* startIp);


    /**
     * @brief Destructor for ClientManager.
     */
    ~ClientManager();

    /**
     * @brief Adds a new client and assigns a server-side VPN IP.
     *
     * @param clientUdpAddr     Public UDP address of client
     * @param androidTunIp      Client’s TUN IP (fixed - ex: 10.8.0.2)
     *
     * Steps:
     *   1. Finds free IP from ipPool
     *   2. Creates Client struct
     *   3. Adds entries to:
     *          vpn_to_client
     *          udp_to_vpn
     *
     * @return uint32_t The server-assigned VPN IP
     *                   (0 if pool exhausted)
     */
    Client* addClient(const sockaddr_in &clientUdpAddr, uint32_t androidTunIp,uint8_t &xor_key);

    /**
     * @brief Removes a client using its server-assigned VPN IP.
     *
     * Also:
     *   - Removes reverse UDP-to-VPN mapping
     *   - Frees IP in pool
     *
     * @param serverAssignedIp The VPN IP previously given to the client
     */
    void removeClient(uint32_t serverAssignedIp);

    /**
     * @brief Get client using server-assigned VPN IP.
     *
     * Used for routing packets coming from the TUN interface.
     *
     * @return Client* Pointer to client or nullptr if not found
     */
    Client* getClientByServerIp(uint32_t ip);

    /**
     * @brief Get client using its real-world UDP address.
     *
     * Used for routing packets coming from the UDP socket.
     *
     * @return Client* Pointer to client or nullptr if not found
     */
    Client* getClientByUdp(const sockaddr_in &addr);

    bool isIpInUse(uint32_t ip) const;
    bool isIpInStateActive(uint32_t ip) const;
    bool makeIpInUse(uint32_t ip);
    uint32_t getNextAvailableIp();
    Client* getClientByClientTunIpAndUdpAddr(const sockaddr_in &addr,uint32_t clientTunIp);
    void freeIp(uint32_t ip);

};

// Client_Manager.h ends here