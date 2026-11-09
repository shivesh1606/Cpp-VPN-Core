#include "auth/Ticket.h"

#include <sodium.h>

#include <cstring>

#include "auth/RevocationList.h"

namespace auth
{

namespace
{
void putU32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = uint8_t(v >> (8 * i));
}
void putU64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = uint8_t(v >> (8 * i));
}
uint32_t getU32(const uint8_t *p)
{
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
uint64_t getU64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = v << 8 | p[i];
    return v;
}

// "cppvpn-ticket-v1" || body: the signed message (domain separation from any other signature
// made with the issuer key, e.g. revocation lists).
void signedMessage(const uint8_t body[kTicketBodyLen], uint8_t *msg, size_t &len)
{
    const size_t ctx = std::strlen(kTicketContext);
    std::memcpy(msg, kTicketContext, ctx);
    std::memcpy(msg + ctx, body, kTicketBodyLen);
    len = ctx + kTicketBodyLen;
}
} // namespace

const char *verdictName(Verdict v)
{
    switch (v)
    {
    case Verdict::kOk: return "ok";
    case Verdict::kFormat: return "format";
    case Verdict::kUnknownKey: return "unknown_key";
    case Verdict::kSig: return "sig";
    case Verdict::kExpired: return "expired";
    case Verdict::kScope: return "scope";
    case Verdict::kDevice: return "device";
    case Verdict::kRevoked: return "revoked";
    default: return "?";
    }
}

void encodeBody(const Ticket &t, uint8_t out[kTicketBodyLen])
{
    out[0] = t.ver;
    out[1] = t.key_id;
    out[2] = t.tier;
    out[3] = 0; // rsvd
    std::memcpy(out + 4, t.user_id, kUserIdLen);
    std::memcpy(out + 20, t.device_pk, 32);
    putU32(out + 52, t.tags);
    putU32(out + 56, t.nbf);
    putU32(out + 60, t.exp);
    putU64(out + 64, t.ticket_id);
}

void encode(const Ticket &t, uint8_t out[kTicketLen])
{
    encodeBody(t, out);
    std::memcpy(out + kTicketBodyLen, t.sig, 64);
}

bool decode(const uint8_t *p, size_t len, Ticket &out)
{
    if (!p || len != kTicketLen || p[0] != kTicketVersion || p[3] != 0)
        return false;
    out.ver = p[0];
    out.key_id = p[1];
    out.tier = p[2];
    std::memcpy(out.user_id, p + 4, kUserIdLen);
    std::memcpy(out.device_pk, p + 20, 32);
    out.tags = getU32(p + 52);
    out.nbf = getU32(p + 56);
    out.exp = getU32(p + 60);
    out.ticket_id = getU64(p + 64);
    std::memcpy(out.sig, p + kTicketBodyLen, 64);
    return true;
}

bool sign(Ticket &t, const uint8_t issuer_sk[64])
{
    uint8_t body[kTicketBodyLen], msg[64 + kTicketBodyLen];
    size_t len = 0;
    encodeBody(t, body);
    signedMessage(body, msg, len);
    return crypto_sign_detached(t.sig, nullptr, msg, len, issuer_sk) == 0;
}

Verdict verify(const uint8_t *bytes, size_t len, const uint8_t s_c[32], uint64_t now_unix,
               const IssuerKeys &issuers, uint32_t node_mask, const RevocationList *revoked, Ticket *out)
{
    Ticket t;
    if (!decode(bytes, len, t))
        return Verdict::kFormat;
    if (out)
        *out = t;
    auto pk = issuers.find(t.key_id);
    if (pk == issuers.end())
        return Verdict::kUnknownKey;
    uint8_t msg[64 + kTicketBodyLen];
    size_t mlen = 0;
    signedMessage(bytes, msg, mlen); // bytes[0:72] exactly as received
    if (crypto_sign_verify_detached(bytes + kTicketBodyLen, msg, mlen, pk->second.data()) != 0)
        return Verdict::kSig;
    if (now_unix + kClockSkewS < t.nbf || now_unix >= uint64_t(t.exp) + kClockSkewS)
        return Verdict::kExpired;
    if ((t.tags & node_mask) == 0)
        return Verdict::kScope;
    if (crypto_verify_32(t.device_pk, s_c) != 0)
        return Verdict::kDevice;
    if (revoked && (revoked->hasUser(t.user_id) || revoked->hasTicket(t.ticket_id)))
        return Verdict::kRevoked;
    return Verdict::kOk;
}

} // namespace auth
