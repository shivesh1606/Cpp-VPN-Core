#include "auth/RevocationList.h"

#include <sodium.h>

#include <cstring>

namespace auth
{

namespace
{
constexpr size_t kHeaderLen = 1 + 1 + 8 + 4 + 4; // 18
constexpr size_t kEntryLen = 1 + 16;
constexpr size_t kSigLen = 64;

void putLE(uint8_t *p, uint64_t v, int n)
{
    for (int i = 0; i < n; i++)
        p[i] = uint8_t(v >> (8 * i));
}
uint64_t getLE(const uint8_t *p, int n)
{
    uint64_t v = 0;
    for (int i = n - 1; i >= 0; i--)
        v = v << 8 | p[i];
    return v;
}
std::vector<uint8_t> signedMessage(const uint8_t *body, size_t len)
{
    const size_t ctx = std::strlen(kRevocationContext);
    std::vector<uint8_t> m(ctx + len);
    std::memcpy(m.data(), kRevocationContext, ctx);
    std::memcpy(m.data() + ctx, body, len);
    return m;
}
} // namespace

const char *listVerdictName(ListVerdict v)
{
    switch (v)
    {
    case ListVerdict::kOk: return "ok";
    case ListVerdict::kFormat: return "format";
    case ListVerdict::kUnknownKey: return "unknown_key";
    case ListVerdict::kSig: return "sig";
    case ListVerdict::kRollback: return "rollback (seq not newer)";
    }
    return "?";
}

void RevocationList::addUser(const uint8_t user_id[kUserIdLen])
{
    users_.insert(std::string(reinterpret_cast<const char *>(user_id), kUserIdLen));
}

void RevocationList::addTicket(uint64_t ticket_id)
{
    tickets_.insert(ticket_id);
}

bool RevocationList::hasUser(const uint8_t user_id[kUserIdLen]) const
{
    return users_.count(std::string(reinterpret_cast<const char *>(user_id), kUserIdLen)) != 0;
}

std::vector<uint8_t> RevocationList::encodeSigned(const uint8_t issuer_sk[64]) const
{
    const size_t count = users_.size() + tickets_.size();
    std::vector<uint8_t> out(kHeaderLen + count * kEntryLen + kSigLen, 0);
    out[0] = kRevocationVersion;
    out[1] = key_id;
    putLE(&out[2], seq, 8);
    putLE(&out[10], issued_at, 4);
    putLE(&out[14], count, 4);
    size_t off = kHeaderLen;
    for (const auto &u : users_)
    {
        out[off] = 1;
        std::memcpy(&out[off + 1], u.data(), kUserIdLen);
        off += kEntryLen;
    }
    for (uint64_t t : tickets_)
    {
        out[off] = 2;
        putLE(&out[off + 1], t, 8); // remaining 8 bytes stay zero
        off += kEntryLen;
    }
    const auto msg = signedMessage(out.data(), off);
    crypto_sign_detached(&out[off], nullptr, msg.data(), msg.size(), issuer_sk);
    return out;
}

ListVerdict parseRevocationList(const uint8_t *p, size_t len, const IssuerKeys &issuers, RevocationList &out)
{
    if (!p || len < kHeaderLen + kSigLen || p[0] != kRevocationVersion)
        return ListVerdict::kFormat;
    const uint64_t count = getLE(p + 14, 4);
    if (count > kMaxRevocationEntries || len != kHeaderLen + count * kEntryLen + kSigLen)
        return ListVerdict::kFormat;
    auto pk = issuers.find(p[1]);
    if (pk == issuers.end())
        return ListVerdict::kUnknownKey;
    const size_t body_len = len - kSigLen;
    const auto msg = signedMessage(p, body_len);
    if (crypto_sign_verify_detached(p + body_len, msg.data(), msg.size(), pk->second.data()) != 0)
        return ListVerdict::kSig;

    RevocationList l;
    l.key_id = p[1];
    l.seq = getLE(p + 2, 8);
    l.issued_at = uint32_t(getLE(p + 10, 4));
    for (size_t i = 0; i < count; i++)
    {
        const uint8_t *e = p + kHeaderLen + i * kEntryLen;
        if (e[0] == 1)
            l.addUser(e + 1);
        else if (e[0] == 2)
        {
            static const uint8_t zeros[8] = {0};
            if (std::memcmp(e + 9, zeros, 8) != 0)
                return ListVerdict::kFormat;
            l.addTicket(getLE(e + 1, 8));
        }
        else
            return ListVerdict::kFormat;
    }
    out = std::move(l);
    return ListVerdict::kOk;
}

ListVerdict RevocationState::update(const uint8_t *p, size_t len, const IssuerKeys &issuers)
{
    RevocationList l;
    const ListVerdict v = parseRevocationList(p, len, issuers, l);
    if (v != ListVerdict::kOk)
        return v;
    if (current_ && l.seq <= current_->seq)
        return ListVerdict::kRollback;
    current_ = std::make_unique<RevocationList>(std::move(l));
    return ListVerdict::kOk;
}

} // namespace auth
