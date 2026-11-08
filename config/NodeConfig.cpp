#include "config/NodeConfig.h"

#include <algorithm>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <functional>
#include <sstream>

#include "crypto/CipherRegistry.h"
#include "crypto/NodeIdentity.h"
#include "net/ip/Cidr.h"

namespace config
{

namespace
{

struct Ctx
{
    NodeConfig &cfg;
    ConfigReport &report;
    std::string where; // "line 7" or "--set"
    std::string name;  // "section.key"

    void error(const std::string &msg) { report.errors.push_back(where + ": " + name + ": " + msg); }
    void warn(const std::string &msg) { report.warnings.push_back(where + ": " + name + ": " + msg); }
};

bool parseInt(const std::string &v, long lo, long hi, long &out)
{
    if (v.empty() || v.find_first_not_of("0123456789") != std::string::npos || v.size() > 9)
        return false;
    out = std::strtol(v.c_str(), nullptr, 10);
    return out >= lo && out <= hi;
}

bool intKey(Ctx &c, const std::string &v, long lo, long hi, int &dst)
{
    long n = 0;
    if (!parseInt(v, lo, hi, n))
    {
        c.error("expected an integer in " + std::to_string(lo) + ".." + std::to_string(hi) +
                ", got '" + v + "'");
        return false;
    }
    dst = static_cast<int>(n);
    return true;
}

bool parseBool(const std::string &v, bool &out)
{
    std::string s = v;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char ch) { return std::tolower(ch); });
    if (s == "true" || s == "yes" || s == "on" || s == "1")
        out = true;
    else if (s == "false" || s == "no" || s == "off" || s == "0")
        out = false;
    else
        return false;
    return true;
}

bool simpleName(const std::string &s, size_t max_len)
{
    if (s.empty() || s.size() > max_len)
        return false;
    for (char ch : s)
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '_' && ch != '-' && ch != '.')
            return false;
    return true;
}

const crypto::CipherBackend *backendByName(const std::string &algorithm, const char *impl)
{
    for (const auto &b : crypto::CipherRegistry::instance().all())
        if (algorithm == b->algorithmName() && (!impl || std::string(impl) == b->implName()))
            return b.get();
    return nullptr;
}

std::string registeredAlgorithms()
{
    std::string s;
    for (uint8_t id : crypto::CipherRegistry::instance().algorithms())
        s += (s.empty() ? "" : ", ") + std::string(crypto::CipherRegistry::instance().find(id)->algorithmName());
    return s;
}

constexpr const char *kNotYetM4 = "accepted, but not used until protocol v2 (milestone M4)";
constexpr const char *kNotYetM5 = "accepted, but not used until tickets (milestone M5)";

using Handler = std::function<void(Ctx &, const std::string &)>;

const std::map<std::string, Handler> &fixedKeys()
{
    static const std::map<std::string, Handler> keys = {
        // ---- [node] ----
        {"node.id", [](Ctx &c, const std::string &v) {
             if (!simpleName(v, 32))
                 return c.error("expected 1-32 characters [A-Za-z0-9_.-]");
             c.cfg.id = v;
         }},
        {"node.tags", [](Ctx &c, const std::string &v) {
             c.cfg.tags = splitList(v);
             for (const auto &t : c.cfg.tags)
                 if (!simpleName(t, 32))
                     return c.error("invalid tag '" + t + "'");
             c.warn(kNotYetM5);
         }},
        {"node.port", [](Ctx &c, const std::string &v) {
             int p = 0;
             if (intKey(c, v, 1, 65535, p))
                 c.cfg.port = static_cast<uint16_t>(p);
         }},
        {"node.node_key", [](Ctx &c, const std::string &v) {
             if (v.empty())
                 return c.error("path must not be empty");
             c.cfg.node_key = v;
         }},
        // ---- [tunnel] ----
        {"tunnel.tun_name", [](Ctx &c, const std::string &v) {
             if (!simpleName(v, 15)) // IFNAMSIZ - 1
                 return c.error("expected 1-15 characters [A-Za-z0-9_.-]");
             c.cfg.tun_name = v;
         }},
        {"tunnel.tun_cidr", [](Ctx &c, const std::string &v) {
             net::Ipv4Cidr cidr;
             std::string err;
             if (!net::parseCidr(v, cidr, err))
                 return c.error(err);
             if (net::poolSize(cidr) == 0)
                 return c.error("no client addresses left after " + net::ipv4ToString(cidr.addr) +
                                " (use the first host address, e.g. x.y.z.1/24)");
             c.cfg.configure_tun = true;
             c.cfg.tun_addr = cidr.addr;
             c.cfg.tun_prefix = cidr.prefix;
             c.cfg.pool_start = net::poolStart(cidr);
             c.cfg.pool_size = net::poolSize(cidr);
         }},
        {"tunnel.mtu", [](Ctx &c, const std::string &v) { intKey(c, v, 576, 1500, c.cfg.mtu); }},
        // ---- [crypto] ----
        {"crypto.algorithms", [](Ctx &c, const std::string &v) {
             const auto list = splitList(v);
             if (list.empty())
                 return c.error("at least one algorithm is required");
             for (const auto &a : list)
                 if (!backendByName(a, nullptr))
                     return c.error("unknown algorithm '" + a + "' (this binary has: " +
                                    registeredAlgorithms() + ")");
             c.cfg.algorithms = list;
             c.warn(kNotYetM4);
         }},
        {"crypto.allow_insecure_xor", [](Ctx &c, const std::string &v) {
             if (!parseBool(v, c.cfg.allow_insecure_xor))
                 c.error("expected true or false, got '" + v + "'");
         }},
        // ---- [auth] ----
        {"auth.mode", [](Ctx &c, const std::string &v) {
             if (v == "open")
                 c.cfg.auth_mode = v;
             else if (v == "allowlist")
                 c.error("'allowlist' needs protocol v2 (milestone M4); this binary only supports "
                         "'open', and refuses to start rather than pretend to authenticate");
             else if (v == "ticket")
                 c.error("'ticket' needs tickets (milestone M5); this binary only supports 'open'");
             else
                 c.error("expected open | allowlist | ticket, got '" + v + "'");
         }},
        {"auth.allowed_clients", [](Ctx &c, const std::string &v) {
             if (v.empty())
                 return c.error("path must not be empty");
             c.cfg.allowed_clients = v;
             c.warn(kNotYetM4);
         }},
        {"auth.revocation_url", [](Ctx &c, const std::string &v) {
             if (v.rfind("https://", 0) != 0)
                 return c.error("must be an https:// URL");
             c.cfg.revocation_url = v;
             c.warn(kNotYetM5);
         }},
        // ---- [timers] ----
        {"timers.pending_expiry_s", [](Ctx &c, const std::string &v) { intKey(c, v, 1, 300, c.cfg.pending_expiry_s); }},
        {"timers.dead_after_s", [](Ctx &c, const std::string &v) { intKey(c, v, 5, 86400, c.cfg.dead_after_s); }},
        {"timers.rekey_after_s", [](Ctx &c, const std::string &v) {
             if (intKey(c, v, 10, 3600, c.cfg.rekey_after_s))
                 c.warn(kNotYetM4);
         }},
        {"timers.reject_after_s", [](Ctx &c, const std::string &v) {
             if (intKey(c, v, 10, 7200, c.cfg.reject_after_s))
                 c.warn(kNotYetM4);
         }},
    };
    return keys;
}

// Keys with a variable part: crypto.impl.<algorithm>, auth.issuer_pk.<key_id>.
bool patternKey(Ctx &c, const std::string &section, const std::string &key, const std::string &v)
{
    if (section == "crypto" && key.rfind("impl.", 0) == 0)
    {
        const std::string alg = key.substr(5);
        if (!backendByName(alg, nullptr))
            c.error("unknown algorithm '" + alg + "' (this binary has: " + registeredAlgorithms() + ")");
        else if (!backendByName(alg, v.c_str()))
            c.error("implementation '" + v + "' of " + alg + " is not in this binary" +
                    (v == "openssl" ? " (build with -DWITH_OPENSSL=ON)" : "") +
                    (v == "libsodium" && alg == "aes256gcm" ? " (this CPU has no hardware AES)" : ""));
        else
        {
            c.cfg.impl[alg] = v;
            c.warn(kNotYetM4);
        }
        return true;
    }
    if (section == "auth" && key.rfind("issuer_pk.", 0) == 0)
    {
        long id = 0;
        uint8_t pk[crypto::kX25519Bytes];
        if (!parseInt(key.substr(10), 1, 255, id))
            c.error("key id must be 1..255");
        else if (!crypto::fromBase64Url(v, pk, sizeof(pk)))
            c.error("expected a 32-byte Ed25519 public key in base64url (43 characters)");
        else
        {
            c.cfg.issuer_pk[static_cast<int>(id)] = v;
            c.warn(kNotYetM5);
        }
        return true;
    }
    return false;
}

const char *kSections[] = {"node", "tunnel", "crypto", "auth", "timers"};

} // namespace

bool parseOverride(const std::string &text, std::string &section, std::string &key,
                   std::string &value, std::string &error)
{
    const size_t eq = text.find('=');
    const size_t dot = text.find('.');
    if (eq == std::string::npos || dot == std::string::npos || dot > eq || dot == 0 || dot + 1 == eq)
    {
        error = "--set expects section.key=value, got '" + text + "'";
        return false;
    }
    section = text.substr(0, dot);
    key = text.substr(dot + 1, eq - dot - 1);
    value = text.substr(eq + 1);
    return true;
}

void applyIni(const IniFile &ini, NodeConfig &cfg, ConfigReport &report)
{
    for (const auto &sk : ini.keys())
    {
        const IniEntry *e = ini.get(sk.first, sk.second);
        Ctx c{cfg, report, e->line > 0 ? "line " + std::to_string(e->line) : std::string("--set"),
              sk.first + "." + sk.second};
        const auto &keys = fixedKeys();
        auto h = keys.find(c.name);
        if (h != keys.end())
            h->second(c, e->value);
        else if (!patternKey(c, sk.first, sk.second, e->value))
        {
            const bool known_section =
                std::find(std::begin(kSections), std::end(kSections), sk.first) != std::end(kSections);
            c.error(known_section ? "unknown key (see deploy/node.conf.example)"
                                  : "unknown section [" + sk.first + "]");
        }
    }
}

NodeConfig loadNodeConfig(const std::string &path, const std::vector<std::string> &overrides,
                          ConfigReport &report)
{
    NodeConfig cfg;
    if (!path.empty())
    {
        std::string text, err;
        IniFile file;
        if (!readTextFile(path, text, err))
            report.errors.push_back(err);
        else if (!file.parse(text, err))
            report.errors.push_back(path + ": " + err);
        else
        {
            cfg.source = path;
            cfg.from_file = true;
            applyIni(file, cfg, report);
        }
    }

    IniFile cli;
    for (const auto &o : overrides)
    {
        std::string s, k, v, err;
        if (parseOverride(o, s, k, v, err))
            cli.set(s, k, v);
        else
            report.errors.push_back(err);
    }
    applyIni(cli, cfg, report);

    // Cross-key rules, checked on the final values.
    const bool wants_xor =
        std::find(cfg.algorithms.begin(), cfg.algorithms.end(), "xor") != cfg.algorithms.end();
    if (wants_xor && !cfg.allow_insecure_xor)
        report.errors.push_back("crypto.algorithms: 'xor' is insecure; it needs "
                                "crypto.allow_insecure_xor = true (benchmarks only)");
    if (cfg.reject_after_s <= cfg.rekey_after_s)
        report.errors.push_back("timers: reject_after_s (" + std::to_string(cfg.reject_after_s) +
                                ") must be greater than rekey_after_s (" +
                                std::to_string(cfg.rekey_after_s) + ")");
    if (cfg.from_file && cfg.node_key.empty())
        cfg.node_key = kDefaultNodeKeyPath;
    return cfg;
}

std::string describe(const NodeConfig &cfg)
{
    std::ostringstream o;
    auto list = [](const std::vector<std::string> &v) {
        std::string s;
        for (const auto &x : v)
            s += (s.empty() ? "" : ", ") + x;
        return s.empty() ? std::string("(none)") : s;
    };
    o << "source            " << cfg.source << "\n";
    o << "node.id           " << (cfg.id.empty() ? "(unset)" : cfg.id) << "\n";
    o << "node.tags         " << list(cfg.tags) << "\n";
    o << "node.port         " << cfg.port << "/udp\n";
    o << "node.node_key     " << (cfg.node_key.empty() ? "(none: protocol v1 only)" : cfg.node_key) << "\n";
    o << "tunnel.tun_name   " << cfg.tun_name << "\n";
    if (cfg.configure_tun)
        o << "tunnel.tun_cidr   " << net::ipv4ToString(cfg.tun_addr) << "/" << cfg.tun_prefix
          << " (set by the server), mtu " << cfg.mtu << "\n";
    else
        o << "tunnel.tun_cidr   (unset: tun0 address is configured outside the server)\n";
    o << "client pool       " << net::ipv4ToString(cfg.pool_start) << " .. "
      << net::ipv4ToString(cfg.pool_start + cfg.pool_size - 1) << " (" << cfg.pool_size << ")\n";
    o << "crypto            algorithms " << list(cfg.algorithms);
    for (const auto &kv : cfg.impl)
        o << "; " << kv.first << "=" << kv.second;
    o << (cfg.allow_insecure_xor ? "; INSECURE xor allowed" : "") << "  [protocol v2, M4]\n";
    o << "auth.mode         " << cfg.auth_mode << "\n";
    o << "timers            pending " << cfg.pending_expiry_s << " s, v1 idle sweep "
      << cfg.dead_after_s << " s, rekey " << cfg.rekey_after_s << " s, reject "
      << cfg.reject_after_s << " s\n";
    return o.str();
}

} // namespace config
