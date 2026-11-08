#include "protocol/v2/Client.h"

#include <sodium.h>

#include <algorithm>

#include "crypto/CipherRegistry.h"
#include "crypto/backends/SodiumAead.h"

namespace v2
{

struct Client::Pending
{
    noise::HandshakeIK hs;
    uint32_t local_idx = 0;
    uint64_t started_ms = 0;
};

struct Client::Session
{
    uint32_t local_idx = 0, remote_idx = 0;
    std::unique_ptr<crypto::SessionLock> rx, tx;
    uint64_t tx_counter = 1; // ACK used 0
    ReplayWindow window;
    Payload2 params;
    uint8_t hsid[kHandshakeIdLen] = {0};
    uint64_t created_ms = 0, last_tx_ms = 0;
};

Client::Client(const ClientConfig &cfg) : cfg_(cfg)
{
    crypto::sodiumReady();
    noise::publicKey(cfg_.static_priv, pub_);
    mac1Key(cfg_.server_pub, mac1_key_server_);
    mac1Key(pub_, mac1_key_self_);
}

Client::~Client()
{
    sodium_memzero(cfg_.static_priv, sizeof(cfg_.static_priv));
}

size_t Client::startHandshake(uint64_t now_ms, uint8_t *out)
{
    auto p = std::make_unique<Pending>();
    do
        p->local_idx = randombytes_random();
    while (p->local_idx == 0 || (current_ && p->local_idx == current_->local_idx) ||
           (previous_ && p->local_idx == previous_->local_idx));
    p->started_ms = now_ms;
    if (!p->hs.initInitiator(cfg_.static_priv, cfg_.server_pub,
                             reinterpret_cast<const uint8_t *>(kPrologue), kPrologueLen))
        return 0;

    Payload1 p1;
    tai64nNow(p1.ts);
    p1.offer = cfg_.offer;
    p1.ticket = cfg_.ticket;
    const std::vector<uint8_t> payload = encodePayload1(p1);

    out[0] = kVersion;
    out[1] = kHsInit;
    putU32(out + 2, p->local_idx);
    size_t n = 0;
    if (!p->hs.writeMessage1(payload.data(), payload.size(), out + kInitHeaderLen, n))
        return 0;
    n += kInitHeaderLen;
    computeMac1(mac1_key_server_, out, n, out + n);
    std::memset(out + n + kMacLen, 0, kMacLen); // mac2 reserved
    pending_ = std::move(p);
    stats_.handshakes++;
    return n + kMacsLen;
}

Client::Event Client::receive(const uint8_t *pkt, size_t len, uint64_t now_ms, uint8_t *out,
                              size_t &out_len, uint8_t *plain, size_t &plain_len)
{
    out_len = plain_len = 0;
    if (len < 2 || pkt[0] != kVersion)
    {
        stats_.tr_drop_format++;
        return Event::kNone;
    }

    if (pkt[1] == kHsResp)
    {
        uint8_t p2buf[kPayload2Len + 16];
        size_t p2len = 0;
        Payload2 p2;
        if (!pending_ || len != kRespLen || getU32(pkt + 6) != pending_->local_idx ||
            !verifyMac1(mac1_key_self_, pkt, len) ||
            !pending_->hs.readMessage2(pkt + kRespHeaderLen, len - kRespHeaderLen - kMacsLen, p2buf, p2len) ||
            !decodePayload2(p2buf, p2len, p2) ||
            std::find(cfg_.offer.begin(), cfg_.offer.end(), p2.cipher_id) == cfg_.offer.end())
        {
            stats_.resp_drop++;
            return Event::kNone;
        }
        auto impl = cfg_.impl.find(p2.cipher_id);
        const crypto::CipherBackend *backend =
            impl != cfg_.impl.end()
                ? crypto::CipherRegistry::instance().find(p2.cipher_id, impl->second.c_str())
                : crypto::CipherRegistry::instance().find(p2.cipher_id);
        if (!backend)
        {
            stats_.resp_drop++;
            return Event::kNone;
        }
        auto s = std::make_unique<Session>();
        s->local_idx = pending_->local_idx;
        s->remote_idx = getU32(pkt + 2);
        s->params = p2;
        s->created_ms = now_ms;
        noise::CipherState c2s, s2c;
        pending_->hs.split(c2s, s2c);
        s->tx = backend->newLock(c2s.key());
        s->rx = backend->newLock(s2c.key());
        std::memcpy(s->hsid, pending_->hs.handshakeHash(), kHandshakeIdLen);
        pending_.reset();

        // ACK {handshake_id} with counter 0 (design 02 D3)
        writeTransportHeader(out, kAck, s->remote_idx, 0);
        s->tx->seal(0, out, kTransportHeaderLen, s->hsid, kHandshakeIdLen, out + kTransportHeaderLen);
        out_len = kAckLen;
        s->last_tx_ms = now_ms;

        previous_ = std::move(current_); // old receive key stays valid for in-flight packets
        current_ = std::move(s);
        return Event::kEstablished;
    }

    TransportHeader h;
    if (!readTransportHeader(pkt, len, h))
    {
        stats_.tr_drop_format++;
        return Event::kNone;
    }
    Session *s = current_ && current_->local_idx == h.receiver_idx     ? current_.get()
                 : previous_ && previous_->local_idx == h.receiver_idx ? previous_.get()
                                                                       : nullptr;
    if (!s)
    {
        stats_.tr_drop_no_session++;
        return Event::kNone;
    }
    if (!s->window.check(h.counter))
    {
        stats_.tr_drop_replay++;
        return Event::kNone;
    }
    if (!s->rx->open(h.counter, pkt, kTransportHeaderLen, pkt + kTransportHeaderLen,
                     len - kTransportHeaderLen, plain))
    {
        stats_.tr_drop_auth++;
        return Event::kNone;
    }
    s->window.update(h.counter);
    plain_len = len - kTransportHeaderLen - s->rx->overhead();
    switch (h.type)
    {
    case kData:
        return Event::kData;
    case kKeepalive:
        plain_len = 0;
        return Event::kKeepalive;
    case kBye:
        plain_len = 0;
        current_.reset();
        previous_.reset();
        return Event::kBye;
    default:
        stats_.tr_drop_format++;
        plain_len = 0;
        return Event::kNone;
    }
}

size_t Client::seal(Session &s, uint8_t type, const uint8_t *in, size_t len, uint64_t now_ms, uint8_t *out)
{
    const uint64_t ctr = s.tx_counter++;
    writeTransportHeader(out, type, s.remote_idx, ctr);
    s.tx->seal(ctr, out, kTransportHeaderLen, in, len, out + kTransportHeaderLen);
    s.last_tx_ms = now_ms;
    return kTransportHeaderLen + len + s.tx->overhead();
}

size_t Client::sealData(const uint8_t *ip_pkt, size_t len, uint64_t now_ms, uint8_t *out)
{
    return current_ ? seal(*current_, kData, ip_pkt, len, now_ms, out) : 0;
}

size_t Client::sealKeepalive(uint64_t now_ms, uint8_t *out)
{
    return current_ ? seal(*current_, kKeepalive, nullptr, 0, now_ms, out) : 0;
}

size_t Client::sealBye(uint64_t now_ms, uint8_t *out)
{
    if (!current_)
        return 0;
    const size_t n = seal(*current_, kBye, nullptr, 0, now_ms, out);
    current_.reset();
    previous_.reset();
    return n;
}

uint32_t Client::tunIp() const { return current_ ? current_->params.tun_ip : 0; }
uint8_t Client::cipherId() const { return current_ ? current_->params.cipher_id : 0; }
uint16_t Client::keepaliveSeconds() const { return current_ ? current_->params.keepalive_s : 0; }
std::string Client::handshakeId() const { return current_ ? handshakeIdHex(current_->hsid) : ""; }
uint64_t Client::sessionAgeMs(uint64_t now_ms) const { return current_ ? now_ms - current_->created_ms : 0; }
uint64_t Client::lastSendMs() const { return current_ ? current_->last_tx_ms : 0; }

} // namespace v2
