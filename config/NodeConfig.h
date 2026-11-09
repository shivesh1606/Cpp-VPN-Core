// NodeConfig.h - node.conf schema, defaults and validation (plan Discussion 4a, N2-N5).
//
// Precedence (N3): built-in defaults < config file < command-line --set overrides.
// The built-in defaults are exactly the constants the server used before M3, so running
// without a config file behaves as before.
//
// Unknown sections or keys are errors (typos must not be silently ignored). Keys that only
// take effect with protocol v2 (M4) or tickets (M5) are validated now and produce a warning
// that they are not active yet. Auth modes other than "open" are rejected until implemented,
// so a config can never claim protection the binary does not provide.
#ifndef CONFIG_NODECONFIG_H
#define CONFIG_NODECONFIG_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "config/Ini.h"

namespace config
{

constexpr const char *kDefaultConfigPath = "/etc/cppvpn/node.conf";
constexpr const char *kDefaultNodeKeyPath = "/etc/cppvpn/node.key";

struct NodeConfig
{
    // Where the values came from: "built-in defaults" or the config file path.
    std::string source = "built-in defaults";
    bool from_file = false;

    // [node]
    std::string id;
    std::vector<std::string> tags; // design 03 section 3 (used from M5)
    uint16_t port = 5555;
    std::string node_key; // empty = no node identity (allowed only without a config file)

    // [tunnel]
    std::string tun_name = "tun0";
    bool configure_tun = false; // true when tun_cidr is set: the server configures the address
    uint32_t tun_addr = 0;      // host order
    int tun_prefix = 0;
    int mtu = 1420;             // applied only when configure_tun
    uint32_t pool_start = 0x0A080002; // 10.8.0.2
    uint32_t pool_size = 100;

    // [crypto] (design 01 section 2.3; negotiation from M4)
    std::vector<std::string> algorithms{"chacha20poly1305", "aes256gcm"};
    std::map<std::string, std::string> impl; // algorithm name -> implementation name
    bool allow_insecure_xor = false;

    // [auth] (design 02 section 7, design 03)
    std::string auth_mode = "open";
    std::string allowed_clients;
    std::map<int, std::string> issuer_pk; // key_id -> base64url Ed25519 public key
    std::string revocation_url;

    // [timers] (design 02 section 7)
    int pending_expiry_s = 10; // pending handshake expiry (v1 and v2)
    int dead_after_s = 60;     // v1 idle sweep; replaced by reject_after_s in M4
    int rekey_after_s = 120;   // M4
    int reject_after_s = 180;  // M4
};

struct ConfigReport
{
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    bool ok() const { return errors.empty(); }
};

// Splits "section.key=value" (key may itself contain dots: crypto.impl.aes256gcm=openssl).
bool parseOverride(const std::string &text, std::string &section, std::string &key,
                   std::string &value, std::string &error);

// Applies `ini` on top of `cfg` and validates the result. Errors name the line ("line 7: ...")
// or "--set" for overrides.
void applyIni(const IniFile &ini, NodeConfig &cfg, ConfigReport &report);

// Builds the effective config: defaults, then the file at `path` (if non-empty), then the
// overrides. When a file is used and node_key is unset, it defaults to kDefaultNodeKeyPath.
NodeConfig loadNodeConfig(const std::string &path, const std::vector<std::string> &overrides,
                          ConfigReport &report);

// Human-readable effective configuration (for --check-config and the startup log).
std::string describe(const NodeConfig &cfg);

} // namespace config

#endif // CONFIG_NODECONFIG_H
