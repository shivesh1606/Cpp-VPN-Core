// Cli.h - vpn_server command line (plan M3).
#ifndef CONFIG_CLI_H
#define CONFIG_CLI_H

#include <string>
#include <vector>

namespace config
{

struct CliOptions
{
    enum Mode
    {
        kRun,         // default: start the server
        kGenKey,      // --gen-key PATH [--force]
        kPubKey,      // --pubkey PATH
        kCheckConfig, // --check-config: validate, print the effective config, exit
        kHelp,
        kVersion,
    };
    Mode mode = kRun;
    std::string config_path;   // --config PATH
    bool config_given = false; // false: use kDefaultConfigPath only if that file exists
    std::vector<std::string> overrides; // --set section.key=value (repeatable)
    std::string key_path;      // for --gen-key / --pubkey
    bool force = false;
};

// Returns false and sets `error` on unknown options, missing values or conflicting modes.
bool parseCli(int argc, const char *const *argv, CliOptions &out, std::string &error);

const char *usageText();

} // namespace config

#endif // CONFIG_CLI_H
