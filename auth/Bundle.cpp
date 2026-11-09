#include "auth/Bundle.h"

#include <sodium.h>

#include <cctype>
#include <cstring>

#include "auth/Ticket.h"
#include "crypto/backends/SodiumAead.h"

namespace auth
{

Bundle::~Bundle()
{
    sodium_memzero(device_sk, sizeof(device_sk));
}

std::vector<uint8_t> encodeBundle(const Bundle &b)
{
    std::vector<uint8_t> out{kBundleVersion, uint8_t(b.nodes.size())};
    for (const auto &n : b.nodes)
    {
        out.push_back(uint8_t(n.id.size()));
        out.insert(out.end(), n.id.begin(), n.id.end());
        out.push_back(uint8_t(n.host.size()));
        out.insert(out.end(), n.host.begin(), n.host.end());
        out.push_back(uint8_t(n.port));
        out.push_back(uint8_t(n.port >> 8));
        out.insert(out.end(), n.pub, n.pub + 32);
        for (int i = 0; i < 4; i++)
            out.push_back(uint8_t(n.tags >> (8 * i)));
    }
    out.insert(out.end(), b.device_sk, b.device_sk + 32);
    out.insert(out.end(), b.ticket.begin(), b.ticket.end());
    return out;
}

bool decodeBundle(const uint8_t *p, size_t len, Bundle &out, std::string &error)
{
    size_t off = 0;
    auto need = [&](size_t n) {
        if (off + n > len)
        {
            error = "bundle truncated";
            return false;
        }
        return true;
    };
    if (!need(2))
        return false;
    if (p[0] != kBundleVersion)
    {
        error = "unsupported bundle version " + std::to_string(p[0]);
        return false;
    }
    const size_t count = p[1];
    off = 2;
    if (count == 0 || count > kMaxBundleNodes)
    {
        error = "bundle must list 1.." + std::to_string(kMaxBundleNodes) + " nodes";
        return false;
    }
    std::vector<BundleNode> nodes;
    for (size_t i = 0; i < count; i++)
    {
        BundleNode n;
        if (!need(1))
            return false;
        size_t l = p[off++];
        if (l == 0 || l > 32 || !need(l))
        {
            error = error.empty() ? "bad node id length" : error;
            return false;
        }
        n.id.assign(reinterpret_cast<const char *>(p + off), l);
        off += l;
        if (!need(1))
            return false;
        l = p[off++];
        if (l == 0 || l > 253 || !need(l))
        {
            error = error.empty() ? "bad host length" : error;
            return false;
        }
        n.host.assign(reinterpret_cast<const char *>(p + off), l);
        off += l;
        if (!need(2 + 32 + 4))
            return false;
        n.port = uint16_t(p[off] | p[off + 1] << 8);
        off += 2;
        std::memcpy(n.pub, p + off, 32);
        off += 32;
        n.tags = uint32_t(p[off]) | uint32_t(p[off + 1]) << 8 | uint32_t(p[off + 2]) << 16 | uint32_t(p[off + 3]) << 24;
        off += 4;
        if (n.port == 0)
        {
            error = "node " + n.id + ": port 0";
            return false;
        }
        nodes.push_back(std::move(n));
    }
    if (!need(32 + kTicketLen))
        return false;
    if (off + 32 + kTicketLen != len)
    {
        error = "unexpected bytes after the ticket";
        return false;
    }
    out.nodes = std::move(nodes);
    std::memcpy(out.device_sk, p + off, 32);
    out.ticket.assign(p + off + 32, p + len);
    return true;
}

std::string bundleToUri(const Bundle &b)
{
    std::vector<uint8_t> raw = encodeBundle(b);
    const int variant = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
    std::string s(sodium_base64_encoded_len(raw.size(), variant), '\0');
    sodium_bin2base64(&s[0], s.size(), raw.data(), raw.size(), variant);
    s.resize(std::strlen(s.c_str()));
    sodium_memzero(raw.data(), raw.size());
    return std::string(kBundleUriPrefix) + s;
}

bool bundleFromText(const std::string &text, Bundle &out, std::string &error)
{
    size_t b = 0, e = text.size();
    while (b < e && std::isspace(static_cast<unsigned char>(text[b])))
        b++;
    while (e > b && std::isspace(static_cast<unsigned char>(text[e - 1])))
        e--;
    std::string s = text.substr(b, e - b);
    const std::string prefix = kBundleUriPrefix;
    if (s.rfind(prefix, 0) == 0)
        s.erase(0, prefix.size());
    if (!crypto::sodiumReady())
    {
        error = "libsodium init failed";
        return false;
    }
    std::vector<uint8_t> raw(s.size()); // decoded size < encoded size
    size_t n = 0;
    const char *end = nullptr;
    if (s.empty() ||
        sodium_base642bin(raw.data(), raw.size(), s.c_str(), s.size(), nullptr, &n, &end,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0 ||
        end != s.c_str() + s.size())
    {
        error = "not a bundle (expected cppvpn://import?b=<base64url>)";
        return false;
    }
    const bool ok = decodeBundle(raw.data(), n, out, error);
    sodium_memzero(raw.data(), raw.size());
    sodium_memzero(&s[0], s.size());
    return ok;
}

} // namespace auth
