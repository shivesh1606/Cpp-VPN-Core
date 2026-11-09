#include "protocol/v2/Server.h"

#include <sodium.h>

#include <algorithm>
#include <cstdio>

#include "crypto/CipherRegistry.h"
#include "crypto/NodeIdentity.h"
#include "crypto/backends/SodiumAead.h"
#include "protocol/noise/Noise.h"
#include "utils/logger.h"

namespace v2
{

struct Server::Peer
{
    std::string s_c;
    uint32_t tun_ip = 0;
    uint32_t current = 0, next = 0, previous = 0; // session indexes; 0 = none
};

struct Server::Session
{
    uint32_t local_idx = 0, remote_idx = 0;
    Peer *peer = nullptr;
    uint8_t cipher_id = 0;
    std::unique_ptr<crypto::SessionLock> rx, tx;
    uint64_t tx_counter = 1; // DATA counters start at 1 (section 3.2)
    ReplayWindow window;
    uint8_t hsid[kHandshakeIdLen] = {0};
    bool active = false;
    uint64_t created_ms = 0, last_rx_ms = 0, last_tx_ms = 0;
    Endpoint ep;
    std::string cache_key;
    std::vector<uint8_t> msg2;
    std::string keylog_line;
    bool has_ticket = false; // ticket mode: who this session belongs to (revocation, logs)
    uint8_t user_id[16] = {0};
    uint64_t ticket_id = 0;
};

namespace
{
std::string shortKey(const std::string &k)
{
    return crypto::toBase64Url(reinterpret_cast<const uint8_t *>(k.data()), k.size()).substr(0, 8);
}
std::string ipStr(uint32_t ip)
{
    return std::to_string(ip >> 24) + "." + std::to_string((ip >> 16) & 255) + "." +
           std::to_string((ip >> 8) & 255) + "." + std::to_string(ip & 255);
}
std::string hexOf(const uint8_t *p, size_t n)
{
    static const char *d = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++)
        s += {d[p[i] >> 4], d[p[i] & 15]};
    return s;
}
} // namespace

Server::Server(const uint8_t static_priv[32], ServerConfig cfg, IpPool &pool)
    : cfg_(std::move(cfg)), pool_(pool)
{
    crypto::sodiumReady();
    std::memcpy(priv_, static_priv, 32);
    noise::publicKey(priv_, pub_);
    mac1Key(pub_, mac1_key_);
}

Server::~Server()
{
    sodium_memzero(priv_, sizeof(priv_));
}

size_t Server::activeSessions() const
{
    size_t n = 0;
    for (const auto &kv : sessions_)
        n += kv.second->active;
    return n;
}

size_t Server::pendingSessions() const
{
    return sessions_.size() - activeSessions();
}

uint32_t Server::newIndex()
{
    for (;;)
    {
        const uint32_t idx = randombytes_random();
        if (idx != 0 && !sessions_.count(idx))
            return idx;
    }
}

Server::Rx Server::receive(const uint8_t *pkt, size_t len, const Endpoint &from, uint64_t now_ms,
                           uint8_t *out, size_t &out_len, uint8_t *plain, size_t &plain_len)
{
    out_len = plain_len = 0;
    if (len < 2 || pkt[0] != kVersion)
    {
        stats_.tr_drop_format++;
        return Rx::kDropped;
    }
    if (pkt[1] == kHsInit)
        return onInit(pkt, len, from, now_ms, out, out_len);
    return onTransport(pkt, len, from, now_ms, plain, plain_len);
}

// ---------------- section 5: HS_INIT pipeline ----------------

Server::Rx Server::onInit(const uint8_t *pkt, size_t len, const Endpoint &from, uint64_t now_ms,
                          uint8_t *out, size_t &out_len)
{
    // 1. size, version
    if (len < kInitMinLen || len > kInitMaxLen)
    {
        stats_.hs_drop_format++;
        return Rx::kDropped;
    }
    // 2. mac1 (silent drop: scanners that don't know S_pub get no answer, G10)
    if (!verifyMac1(mac1_key_, pkt, len))
    {
        stats_.hs_drop_mac1++;
        return Rx::kDropped;
    }
    // 3. retransmission of a msg1 we already answered: resend the cached msg2 (G8)
    uint8_t digest[16];
    crypto_generichash(digest, sizeof(digest), pkt, len, nullptr, 0);
    const std::string cache_key(reinterpret_cast<char *>(digest), sizeof(digest));
    auto cached = msg2_cache_.find(cache_key);
    if (cached != msg2_cache_.end())
    {
        Session &s = *sessions_.at(cached->second);
        std::memcpy(out, s.msg2.data(), s.msg2.size());
        out_len = s.msg2.size();
        stats_.hs_retransmit++;
        return Rx::kReply;
    }
    // 4. Noise: es -> s_c, ss -> payload
    noise::HandshakeIK hs;
    uint8_t payload[kInitMaxLen];
    size_t payload_len = 0;
    const uint8_t *noise_msg = pkt + kInitHeaderLen;
    const size_t noise_len = len - kInitHeaderLen - kMacsLen;
    if (!hs.initResponder(priv_, reinterpret_cast<const uint8_t *>(kPrologue), kPrologueLen) ||
        !hs.readMessage1(noise_msg, noise_len, payload, payload_len))
    {
        stats_.hs_drop_decrypt++;
        return Rx::kDropped;
    }
    Payload1 p1;
    if (!decodePayload1(payload, payload_len, p1))
    {
        stats_.hs_drop_format++;
        return Rx::kDropped;
    }
    const std::string s_c(reinterpret_cast<const char *>(hs.remoteStatic()), 32);
    // 5. authentication
    AuthResult auth;
    if (cfg_.auth == ServerConfig::kAllowlist && !cfg_.allowed.count(s_c))
    {
        stats_.hs_drop_auth++;
        LOG(LOG_INFO, "v2 handshake rejected: client %s not in allowed_clients", shortKey(s_c).c_str());
        return Rx::kDropped;
    }
    if (cfg_.auth == ServerConfig::kTicket)
    {
        if (cfg_.authenticator)
            auth = cfg_.authenticator->authenticate(hs.remoteStatic(), p1.ticket);
        else
            auth.reason = 1;
        if (auth.reason)
        {
            stats_.hs_drop_ticket[auth.reason < kTicketReasons ? auth.reason : kTicketReasons - 1]++;
            LOG(LOG_INFO, "v2 handshake rejected: client %s ticket=%016llx reason=%s", shortKey(s_c).c_str(),
                (unsigned long long)auth.ticket_id, auth.reason_name[0] ? auth.reason_name : std::to_string(auth.reason).c_str());
            return Rx::kDropped;
        }
    }
    // 6. replay: timestamp must be newer than any seen for this client (G6)
    const std::string ts(reinterpret_cast<const char *>(p1.ts), kTai64nLen);
    auto last = last_ts_.find(s_c);
    if (last != last_ts_.end() && ts <= last->second) // big-endian bytes: string order == time order
    {
        stats_.hs_drop_replay++;
        return Rx::kDropped;
    }
    // 7. cipher negotiation: first server preference the client also offers (design 01 section 2.3)
    const crypto::CipherBackend *backend = nullptr;
    for (uint8_t id : cfg_.algorithms)
    {
        if (std::find(p1.offer.begin(), p1.offer.end(), id) == p1.offer.end())
            continue;
        if (id == crypto::kCipherXor && !cfg_.allow_insecure_xor)
            continue;
        auto impl = cfg_.impl.find(id);
        backend = impl != cfg_.impl.end() ? crypto::CipherRegistry::instance().find(id, impl->second.c_str())
                                          : crypto::CipherRegistry::instance().find(id);
        if (backend)
            break;
    }
    if (!backend)
    {
        stats_.hs_drop_no_cipher++;
        return Rx::kDropped;
    }
    // 8. address: a known peer keeps its IP (rekey); a new peer gets the first allocation here
    auto peer_it = peers_.find(s_c);
    uint32_t tun_ip = peer_it != peers_.end() ? peer_it->second->tun_ip : pool_.allocate();
    if (tun_ip == 0)
    {
        stats_.hs_drop_pool_empty++;
        return Rx::kDropped;
    }
    // 9. msg2, Split, locks
    auto s = std::make_unique<Session>();
    s->local_idx = newIndex();
    s->remote_idx = getU32(pkt + 2);
    s->cipher_id = backend->algorithmId();
    s->created_ms = s->last_rx_ms = s->last_tx_ms = now_ms;
    s->ep = from;
    s->cache_key = cache_key;
    if (cfg_.auth == ServerConfig::kTicket)
    {
        s->has_ticket = true;
        std::memcpy(s->user_id, auth.user_id, 16);
        s->ticket_id = auth.ticket_id;
    }

    Payload2 p2{tun_ip, s->cipher_id, cfg_.keepalive_s};
    uint8_t p2buf[kPayload2Len];
    encodePayload2(p2, p2buf);
    out[0] = kVersion;
    out[1] = kHsResp;
    putU32(out + 2, s->local_idx);
    putU32(out + 6, s->remote_idx);
    size_t n = 0;
    if (!hs.writeMessage2(p2buf, sizeof(p2buf), out + kRespHeaderLen, n))
    {
        if (peer_it == peers_.end())
            pool_.release(tun_ip);
        stats_.hs_drop_decrypt++; // low-order e_c is caught here for the ee DH
        return Rx::kDropped;
    }
    n += kRespHeaderLen;
    uint8_t client_mac1_key[32];
    mac1Key(hs.remoteStatic(), client_mac1_key); // msg2 mac1 is keyed by the client's key
    computeMac1(client_mac1_key, out, n, out + n);
    std::memset(out + n + kMacLen, 0, kMacLen); // mac2 reserved (D2)
    out_len = n + kMacsLen;

    noise::CipherState c2s, s2c;
    hs.split(c2s, s2c);
    s->rx = backend->newLock(c2s.key());
    s->tx = backend->newLock(s2c.key());
    std::memcpy(s->hsid, hs.handshakeHash(), kHandshakeIdLen);
    if (keylog)
        s->keylog_line = hexOf(s->hsid, kHandshakeIdLen) + " " + std::to_string(s->local_idx) + " " +
                         hexOf(c2s.key(), 32) + " " + hexOf(s2c.key(), 32);
    s->msg2.assign(out, out + out_len);

    // 10. store PENDING; replace an older pending handshake of the same client
    Peer *peer;
    if (peer_it == peers_.end())
    {
        auto np = std::make_unique<Peer>();
        np->s_c = s_c;
        np->tun_ip = tun_ip;
        peer = np.get();
        peers_[s_c] = std::move(np);
        by_tun_[tun_ip] = peer;
    }
    else
        peer = peer_it->second.get();
    if (peer->next)
    {
        stats_.hs_replaced++;
        removeSession(peer->next, "replaced by a newer handshake", true);
    }
    s->peer = peer;
    peer->next = s->local_idx;
    msg2_cache_[cache_key] = s->local_idx;
    last_ts_[s_c] = ts;
    const bool rekey = peer->current != 0;
    char who[64] = "";
    if (s->has_ticket)
        std::snprintf(who, sizeof(who), " user=%s ticket=%016llx", hexOf(s->user_id, 4).c_str(),
                      (unsigned long long)s->ticket_id);
    LOG(LOG_INFO, "v2 %s: hsid=%s idx=%u client=%s ip=%s cipher=%s/%s%s state=PENDING",
        rekey ? "rekey" : "handshake", handshakeIdHex(s->hsid).c_str(), s->local_idx,
        shortKey(s_c).c_str(), ipStr(tun_ip).c_str(), backend->algorithmName(), backend->implName(), who);
    sessions_[s->local_idx] = std::move(s);
    stats_.hs_resp_sent++;
    return Rx::kReply;
}

// ---------------- transport ----------------

Server::Rx Server::onTransport(const uint8_t *pkt, size_t len, const Endpoint &from, uint64_t now_ms,
                               uint8_t *plain, size_t &plain_len)
{
    TransportHeader h;
    if (!readTransportHeader(pkt, len, h))
    {
        stats_.tr_drop_format++;
        return Rx::kDropped;
    }
    auto it = sessions_.find(h.receiver_idx);
    if (it == sessions_.end())
    {
        stats_.tr_drop_no_session++;
        return Rx::kDropped;
    }
    Session &s = *it->second;
    if (!s.window.check(h.counter))
    {
        stats_.tr_drop_replay++;
        return Rx::kDropped;
    }
    if (!s.rx->open(h.counter, pkt, kTransportHeaderLen, pkt + kTransportHeaderLen,
                    len - kTransportHeaderLen, plain))
    {
        stats_.tr_drop_auth++;
        return Rx::kDropped;
    }
    plain_len = len - kTransportHeaderLen - s.rx->overhead();
    // Authenticated from here on: only now may the packet move the window or the endpoint.
    s.window.update(h.counter);
    s.last_rx_ms = now_ms;
    if (s.ep != from)
    {
        s.ep = from; // roaming (section 6): endpoint follows the last authenticated packet
        stats_.roams++;
    }

    switch (h.type)
    {
    case kAck:
        if (h.counter != 0 || plain_len != kHandshakeIdLen ||
            sodium_memcmp(plain, s.hsid, kHandshakeIdLen) != 0)
        {
            stats_.tr_drop_ack++;
            return Rx::kDropped;
        }
        if (!s.active)
            confirm(s, true, now_ms);
        plain_len = 0;
        return Rx::kConsumed;
    case kData:
    {
        // The inner source must be the client's own address (no spoofing through the tunnel).
        const uint32_t src = plain_len >= 20 && (plain[0] >> 4) == 4
                                 ? uint32_t(plain[12]) << 24 | uint32_t(plain[13]) << 16 |
                                       uint32_t(plain[14]) << 8 | plain[15]
                                 : 0;
        if (src != s.peer->tun_ip)
        {
            stats_.tr_drop_src_ip++;
            return Rx::kDropped;
        }
        if (!s.active)
            confirm(s, false, now_ms);
        return Rx::kDeliver;
    }
    case kKeepalive:
        if (!s.active)
            confirm(s, false, now_ms);
        plain_len = 0;
        return Rx::kConsumed;
    case kBye:
    {
        LOG(LOG_INFO, "v2 BYE: hsid=%s client=%s", handshakeIdHex(s.hsid).c_str(),
            shortKey(s.peer->s_c).c_str());
        Peer *p = s.peer;
        const uint32_t ids[] = {p->current, p->next, p->previous};
        for (uint32_t id : ids) // removing the last session also frees the peer and its IP
            if (id)
                removeSession(id, "BYE");
        stats_.removed_bye++;
        plain_len = 0;
        return Rx::kConsumed;
    }
    default:
        stats_.tr_drop_format++;
        return Rx::kDropped;
    }
}

void Server::confirm(Session &s, bool by_ack, uint64_t now_ms)
{
    Peer &p = *s.peer;
    s.active = true;
    s.last_tx_ms = now_ms;
    msg2_cache_.erase(s.cache_key);
    s.msg2.clear();
    s.msg2.shrink_to_fit();
    if (p.next == s.local_idx)
        p.next = 0;
    if (p.current && p.current != s.local_idx)
    {
        if (p.previous)
            removeSession(p.previous, "superseded");
        p.previous = p.current; // still accepted on receive for in-flight packets
        stats_.rekeys++;
    }
    p.current = s.local_idx;
    pool_.activate(p.tun_ip);
    (by_ack ? stats_.hs_confirm_ack : stats_.hs_confirm_data)++;
    LOG(LOG_INFO, "v2 session ACTIVE: hsid=%s idx=%u ip=%s confirm=%s", handshakeIdHex(s.hsid).c_str(),
        s.local_idx, ipStr(p.tun_ip).c_str(), by_ack ? "ack" : "data");
    if (keylog && !s.keylog_line.empty())
        keylog(s.keylog_line);
    sodium_memzero(&s.keylog_line[0], s.keylog_line.size());
    s.keylog_line.clear();
}

void Server::removeSession(uint32_t local_idx, const char *reason, bool keep_peer)
{
    auto it = sessions_.find(local_idx);
    if (it == sessions_.end())
        return;
    Session &s = *it->second;
    Peer *p = s.peer;
    msg2_cache_.erase(s.cache_key);
    if (p->current == local_idx)
        p->current = 0;
    if (p->next == local_idx)
        p->next = 0;
    if (p->previous == local_idx)
        p->previous = 0;
    LOG(LOG_INFO, "v2 session removed: hsid=%s idx=%u reason=%s", handshakeIdHex(s.hsid).c_str(),
        local_idx, reason);
    sessions_.erase(it);
    if (!keep_peer && !p->current && !p->next && !p->previous)
    {
        pool_.release(p->tun_ip);
        by_tun_.erase(p->tun_ip);
        peers_.erase(p->s_c); // deletes p; last_ts_ is kept (replay protection, G6)
    }
}

size_t Server::sealPacket(Session &s, uint8_t type, const uint8_t *in, size_t len, uint64_t now_ms,
                          uint8_t *out)
{
    const uint64_t ctr = s.tx_counter++;
    writeTransportHeader(out, type, s.remote_idx, ctr);
    s.tx->seal(ctr, out, kTransportHeaderLen, in, len, out + kTransportHeaderLen);
    s.last_tx_ms = now_ms;
    return kTransportHeaderLen + len + s.tx->overhead();
}

bool Server::seal(uint32_t dst_tun_ip, const uint8_t *ip_pkt, size_t len, uint64_t now_ms, uint8_t *out,
                  size_t &out_len, Endpoint &to)
{
    auto it = by_tun_.find(dst_tun_ip);
    if (it == by_tun_.end() || !it->second->current)
        return false;
    Session &s = *sessions_.at(it->second->current);
    out_len = sealPacket(s, kData, ip_pkt, len, now_ms, out);
    to = s.ep;
    return true;
}

size_t Server::revoke(const std::function<bool(const uint8_t user_id[16], uint64_t ticket_id)> &revoked,
                      uint64_t now_ms, std::vector<Outgoing> &out)
{
    std::set<Peer *> hit;
    for (auto &kv : sessions_)
        if (kv.second->has_ticket && revoked(kv.second->user_id, kv.second->ticket_id))
            hit.insert(kv.second->peer);
    for (Peer *p : hit)
    {
        if (p->current)
        {
            Session &s = *sessions_.at(p->current);
            Outgoing o; // tell the client right away instead of letting it time out
            o.to = s.ep;
            o.pkt.resize(kTransportMinLen);
            o.pkt.resize(sealPacket(s, kBye, nullptr, 0, now_ms, o.pkt.data()));
            out.push_back(std::move(o));
        }
        const uint32_t ids[] = {p->current, p->next, p->previous};
        for (uint32_t id : ids)
            if (id)
                removeSession(id, "revoked"); // the last one frees the peer and its IP
        stats_.removed_revoked++;
    }
    return hit.size();
}

void Server::tick(uint64_t now_ms, std::vector<Outgoing> &out)
{
    std::vector<std::pair<uint32_t, const char *>> remove;
    for (auto &kv : sessions_)
    {
        Session &s = *kv.second;
        if (!s.active)
        {
            if (now_ms - s.created_ms >= cfg_.pending_expiry_ms)
            {
                stats_.hs_expired++;
                remove.emplace_back(s.local_idx, "pending expired (no ACK/DATA)");
            }
            continue;
        }
        if (now_ms - s.created_ms >= cfg_.reject_after_ms)
        {
            stats_.removed_reject++;
            remove.emplace_back(s.local_idx, "reject-after (key too old, no rekey)");
        }
        else if (now_ms - s.last_rx_ms >= cfg_.reject_after_ms)
        {
            stats_.removed_idle++;
            remove.emplace_back(s.local_idx, "idle (no authenticated packet)");
        }
        else if (s.peer->current == s.local_idx && cfg_.keepalive_s &&
                 now_ms - s.last_tx_ms >= uint64_t(cfg_.keepalive_s) * 1000)
        {
            Outgoing o;
            o.to = s.ep;
            o.pkt.resize(kTransportMinLen);
            o.pkt.resize(sealPacket(s, kKeepalive, nullptr, 0, now_ms, o.pkt.data()));
            out.push_back(std::move(o));
        }
    }
    for (const auto &r : remove)
        removeSession(r.first, r.second);
}

} // namespace v2
