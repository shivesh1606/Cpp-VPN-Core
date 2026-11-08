#include "config/Cli.h"

namespace config
{

const char *usageText()
{
    return "Usage: vpn_server [options]\n"
           "\n"
           "  --config PATH        node config (default /etc/cppvpn/node.conf if it exists,\n"
           "                       otherwise built-in defaults = protocol v1 behaviour)\n"
           "  --set S.KEY=VALUE    override one config value, e.g. --set node.port=6000\n"
           "                       (repeatable; applied after the file)\n"
           "  --check-config       validate the config (and node key), print it, exit\n"
           "  --gen-key PATH       create the node's X25519 key (mode 0600), print its public key\n"
           "  --force              with --gen-key: replace an existing key (changes the identity!)\n"
           "  --pubkey PATH        print the public key of an existing node key\n"
           "  --version            print the version\n"
           "  --help               this text\n"
           "\n"
           "Reference config with every key documented: deploy/node.conf.example\n";
}

bool parseCli(int argc, const char *const *argv, CliOptions &out, std::string &error)
{
    CliOptions o;
    int modes = 0;
    auto setMode = [&](CliOptions::Mode m) {
        o.mode = m;
        modes++;
    };
    for (int i = 1; i < argc; i++)
    {
        const std::string a = argv[i];
        auto value = [&](std::string &dst) {
            if (i + 1 >= argc || std::string(argv[i + 1]).rfind("--", 0) == 0)
            {
                error = a + " needs a value";
                return false;
            }
            dst = argv[++i];
            return true;
        };
        if (a == "--config")
        {
            if (!value(o.config_path))
                return false;
            o.config_given = true;
        }
        else if (a == "--set")
        {
            std::string v;
            if (!value(v))
                return false;
            o.overrides.push_back(v);
        }
        else if (a == "--gen-key")
        {
            if (!value(o.key_path))
                return false;
            setMode(CliOptions::kGenKey);
        }
        else if (a == "--pubkey")
        {
            if (!value(o.key_path))
                return false;
            setMode(CliOptions::kPubKey);
        }
        else if (a == "--force")
            o.force = true;
        else if (a == "--check-config")
            setMode(CliOptions::kCheckConfig);
        else if (a == "--help" || a == "-h")
            setMode(CliOptions::kHelp);
        else if (a == "--version")
            setMode(CliOptions::kVersion);
        else
        {
            error = "unknown option '" + a + "' (see --help)";
            return false;
        }
    }
    if (modes > 1)
    {
        error = "--gen-key, --pubkey, --check-config, --help and --version are mutually exclusive";
        return false;
    }
    if (o.force && o.mode != CliOptions::kGenKey)
    {
        error = "--force is only valid with --gen-key";
        return false;
    }
    out = o;
    return true;
}

} // namespace config
