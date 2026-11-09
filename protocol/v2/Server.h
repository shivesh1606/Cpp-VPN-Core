// Server.h - protocol v2 responder engine (design doc 02, sections 5-8). Socket-free:
// packets and the current time go in; replies, plaintext and counters come out. main.cpp does I/O.
//
//   receive(HS_INIT)  -> section 5 pipeline (cheapest check first, first IP allocation at step 8)
//   receive(ACK)      -> PENDING -> ACTIVE ("confirm=ack")
//   receive(DATA/KA)  -> replay window, open(), roaming, inner source check; confirms a PENDING
//                        session as a fallback ("confirm=data") when the ACK was lost (D3)
//   seal()            -> DATA for the ACTIVE session that owns a tun IP
//   tick()            -> pending expiry, reject-after, idle removal, server keepalives
//
// Sessions per client static key s_c ("peer"): current (ACTIVE), next (PENDING; a new client or a
// rekey) and previous (the replaced key, still accepted on receive until it ages out).
// The tun IP belongs to the peer, so a rekey keeps the client's address.
#ifndef PROTOCOL_V2_SERVER_H
#define PROTOCOL_V2_SERVER_H

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "crypto/SessionLock.h"
#include "protocol/v2/ReplayWindow.h"
#include "protocol/v2/Wire.h"

namespace v2
{

// The client address pool shared with protocol v1 (ClientManager in main.cpp).
class IpPool
{
public:
    virtual ~IpPool() = default;
    virtual uint32_t allocate() = 0; // reserve a free address (host order); 0 = pool empty
    virtual void activate(uint32_t ip) = 0;
    virtual void release(uint32_t ip) = 0;
};

// UDP endpoint, network byte order (as in sockaddr_in).
struct Endpoint
{
    uint32_t addr = 0;
    uint16_t port = 0;
    bool operator==(const Endpoint &o) const { return addr == o.addr && port == o.port; }
    bool operator!=(const Endpoint &o) const { return !(*this == o); }
};

struct ServerConfig
{
    enum Auth
    {
        kOpen,      // any client key (development only; refused by config unless -DALLOW_OPEN_AUTH)
        kAllowlist, // s_c must be in `allowed`
    };
    Auth auth = kAllowlist;
    std::set<std::string> allowed;            // 32-byte client public keys
    std::vector<uint8_t> algorithms{1, 2};    // server preference (cipher ids)
    std::map<uint8_t, std::string> impl;      // cipher id -> implementation name
    bool allow_insecure_xor = false;
    uint16_t keepalive_s = 15;
    uint32_t pending_expiry_ms = 10000;
    uint32_t reject_after_ms = 180000;
};

struct ServerStats
{
    // handshake (section 8 drop reasons; each failed HS_INIT increments exactly one)
    uint64_t hs_drop_format = 0, hs_drop_mac1 = 0, hs_drop_decrypt = 0, hs_drop_auth = 0,
             hs_drop_replay = 0, hs_drop_no_cipher = 0, hs_drop_pool_empty = 0;
    uint64_t hs_resp_sent = 0, hs_retransmit = 0, hs_confirm_ack = 0, hs_confirm_data = 0,
             hs_expired = 0, hs_replaced = 0, rekeys = 0;
    // transport
    uint64_t tr_drop_format = 0, tr_drop_no_session = 0, tr_drop_replay = 0, tr_drop_auth = 0,
             tr_drop_src_ip = 0, tr_drop_ack = 0, roams = 0;
    uint64_t removed_bye = 0, removed_reject = 0, removed_idle = 0;
};

class Server
{
public:
    enum class Rx
    {
        kDropped,   // see stats
        kReply,     // `out` holds a packet to send back to the sender (HS_RESP)
        kDeliver,   // `plain` holds an IPv4 packet for the TUN device
        kConsumed,  // ACK / KEEPALIVE / BYE handled
    };
    struct Outgoing
    {
        Endpoint to;
        std::vector<uint8_t> pkt;
    };

    Server(const uint8_t static_priv[32], ServerConfig cfg, IpPool &pool);
    ~Server();

    // Any packet whose first byte is kVersion. `out` needs kRespLen bytes, `plain` needs `len`.
    Rx receive(const uint8_t *pkt, size_t len, const Endpoint &from, uint64_t now_ms, uint8_t *out,
               size_t &out_len, uint8_t *plain, size_t &plain_len);

    // DATA for the ACTIVE session owning `dst_tun_ip`. `out` needs len + kTransportMinLen bytes.
    bool seal(uint32_t dst_tun_ip, const uint8_t *ip_pkt, size_t len, uint64_t now_ms, uint8_t *out,
              size_t &out_len, Endpoint &to);
    bool ownsTunIp(uint32_t ip) const { return by_tun_.count(ip) != 0; }

    void tick(uint64_t now_ms, std::vector<Outgoing> &out);

    const ServerStats &stats() const { return stats_; }
    size_t activeSessions() const;
    size_t pendingSessions() const;
    const uint8_t *publicKey() const { return pub_; }

    // Called with "handshake_id receiver_idx k_c2s k_s2c" (hex) per confirmed session when set
    // (ENABLE_KEYLOG builds only; design 02 section 8).
    std::function<void(const std::string &)> keylog;

private:
    struct Peer;
    struct Session;

    Rx onInit(const uint8_t *pkt, size_t len, const Endpoint &from, uint64_t now_ms, uint8_t *out,
              size_t &out_len);
    Rx onTransport(const uint8_t *pkt, size_t len, const Endpoint &from, uint64_t now_ms,
                   uint8_t *plain, size_t &plain_len);
    void confirm(Session &s, bool by_ack, uint64_t now_ms);
    // Removes a session; when the peer has none left it is removed too and its IP released,
    // unless `keep_peer` (a pending handshake being replaced by a newer one).
    void removeSession(uint32_t local_idx, const char *reason, bool keep_peer = false);
    uint32_t newIndex();
    size_t sealPacket(Session &s, uint8_t type, const uint8_t *in, size_t len, uint64_t now_ms, uint8_t *out);

    uint8_t priv_[32], pub_[32], mac1_key_[32];
    ServerConfig cfg_;
    IpPool &pool_;
    ServerStats stats_;
    std::unordered_map<uint32_t, std::unique_ptr<Session>> sessions_; // by local (receiver) index
    std::unordered_map<std::string, std::unique_ptr<Peer>> peers_;     // by s_c
    std::unordered_map<uint32_t, Peer *> by_tun_;                       // by tun IP (TX path)
    std::unordered_map<std::string, uint32_t> msg2_cache_;              // hash(msg1) -> pending idx
    std::unordered_map<std::string, std::string> last_ts_;              // s_c -> newest TAI64N (G6)
};

} // namespace v2

#endif // PROTOCOL_V2_SERVER_H
