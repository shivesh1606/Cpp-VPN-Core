// Client.h - protocol v2 initiator engine (design doc 02, section 4). Socket-free and portable:
// used by the Linux test client (tools/v2_client.cpp) and the Windows client.
//
//   startHandshake()  -> HS_INIT (fresh ephemeral, fresh TAI64N, fresh sender_idx). Call again
//                        after 5 s without a response (new msg1 each attempt), or for a rekey.
//   receive(HS_RESP)  -> verify, Split, locks; returns kEstablished and the ACK to send
//   receive(DATA...)  -> replay window + open(); kData puts an IPv4 packet in `plain`
//   sealData / sealKeepalive / sealBye
//
// During a rekey the old session keeps working until the new HS_RESP arrives; after the switch the
// old receive key is kept, so packets the server sent before it saw our ACK still decrypt.
#ifndef PROTOCOL_V2_CLIENT_H
#define PROTOCOL_V2_CLIENT_H

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "crypto/SessionLock.h"
#include "protocol/noise/Noise.h"
#include "protocol/v2/ReplayWindow.h"
#include "protocol/v2/Wire.h"

namespace v2
{

struct ClientConfig
{
    uint8_t static_priv[32] = {0}; // the device key (its public half is what the server allows)
    uint8_t server_pub[32] = {0};  // S_pub of the node (from the bundle / node.conf owner)
    std::vector<uint8_t> offer{1, 2};    // cipher ids in client preference order
    std::vector<uint8_t> ticket;         // design 03 (M5); empty for allowlist nodes
    std::map<uint8_t, std::string> impl; // optional implementation per cipher id
};

struct ClientStats
{
    uint64_t resp_drop = 0, tr_drop_format = 0, tr_drop_no_session = 0, tr_drop_replay = 0,
             tr_drop_auth = 0, handshakes = 0;
};

class Client
{
public:
    enum class Event
    {
        kNone,        // nothing for the caller (or a dropped packet, see stats)
        kEstablished, // `out` holds the ACK to send now
        kData,        // `plain` holds an IPv4 packet from the server
        kKeepalive,
        kBye,         // server ended the session
    };

    explicit Client(const ClientConfig &cfg);
    ~Client();

    // Writes HS_INIT into `out` (>= kInitMaxLen) and returns its length (0 on failure).
    size_t startHandshake(uint64_t now_ms, uint8_t *out);
    bool handshakeInFlight() const { return pending_ != nullptr; }

    // `out` needs kAckLen bytes, `plain` needs `len` bytes.
    Event receive(const uint8_t *pkt, size_t len, uint64_t now_ms, uint8_t *out, size_t &out_len,
                  uint8_t *plain, size_t &plain_len);

    // Transport packets for the current session; `out` needs len + kTransportMinLen. 0 if none.
    size_t sealData(const uint8_t *ip_pkt, size_t len, uint64_t now_ms, uint8_t *out);
    size_t sealKeepalive(uint64_t now_ms, uint8_t *out);
    size_t sealBye(uint64_t now_ms, uint8_t *out);

    bool established() const { return current_ != nullptr; }
    uint32_t tunIp() const;        // host order
    uint8_t cipherId() const;
    uint16_t keepaliveSeconds() const;
    std::string handshakeId() const;
    uint64_t sessionAgeMs(uint64_t now_ms) const;
    uint64_t lastSendMs() const;   // for keepalive scheduling
    const uint8_t *publicKey() const { return pub_; }
    const ClientStats &stats() const { return stats_; }

private:
    struct Pending;
    struct Session;
    size_t seal(Session &s, uint8_t type, const uint8_t *in, size_t len, uint64_t now_ms, uint8_t *out);

    ClientConfig cfg_;
    uint8_t pub_[32] = {0}, mac1_key_server_[32] = {0}, mac1_key_self_[32] = {0};
    std::unique_ptr<Pending> pending_;
    std::unique_ptr<Session> current_, previous_;
    ClientStats stats_;
};

} // namespace v2

#endif // PROTOCOL_V2_CLIENT_H
