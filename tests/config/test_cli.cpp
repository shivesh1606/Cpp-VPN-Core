// vpn_server command line (plan M3).
#include <gtest/gtest.h>

#include "config/Cli.h"

using config::CliOptions;

namespace
{
bool parse(std::vector<const char *> args, CliOptions &o, std::string &err)
{
    args.insert(args.begin(), "vpn_server");
    return config::parseCli(static_cast<int>(args.size()), args.data(), o, err);
}
} // namespace

TEST(Cli, NoArgumentsRunsWithoutExplicitConfig)
{
    CliOptions o;
    std::string err;
    ASSERT_TRUE(parse({}, o, err)) << err;
    EXPECT_EQ(o.mode, CliOptions::kRun);
    EXPECT_FALSE(o.config_given);
    EXPECT_TRUE(o.overrides.empty());
}

TEST(Cli, ConfigAndRepeatedOverrides)
{
    CliOptions o;
    std::string err;
    ASSERT_TRUE(parse({"--config", "/tmp/n.conf", "--set", "node.port=6000", "--set",
                       "crypto.impl.aes256gcm=openssl"},
                      o, err))
        << err;
    EXPECT_TRUE(o.config_given);
    EXPECT_EQ(o.config_path, "/tmp/n.conf");
    EXPECT_EQ(o.overrides, (std::vector<std::string>{"node.port=6000", "crypto.impl.aes256gcm=openssl"}));
}

TEST(Cli, Modes)
{
    CliOptions o;
    std::string err;
    ASSERT_TRUE(parse({"--gen-key", "/k", "--force"}, o, err)) << err;
    EXPECT_EQ(o.mode, CliOptions::kGenKey);
    EXPECT_EQ(o.key_path, "/k");
    EXPECT_TRUE(o.force);
    ASSERT_TRUE(parse({"--pubkey", "/k"}, o, err));
    EXPECT_EQ(o.mode, CliOptions::kPubKey);
    ASSERT_TRUE(parse({"--check-config", "--config", "x"}, o, err));
    EXPECT_EQ(o.mode, CliOptions::kCheckConfig);
    ASSERT_TRUE(parse({"-h"}, o, err));
    EXPECT_EQ(o.mode, CliOptions::kHelp);
    ASSERT_TRUE(parse({"--version"}, o, err));
    EXPECT_EQ(o.mode, CliOptions::kVersion);
}

TEST(Cli, Errors)
{
    CliOptions o;
    std::string err;
    EXPECT_FALSE(parse({"--bogus"}, o, err));
    EXPECT_EQ(err, "unknown option '--bogus' (see --help)");
    EXPECT_FALSE(parse({"--config"}, o, err));
    EXPECT_EQ(err, "--config needs a value");
    EXPECT_FALSE(parse({"--config", "--set"}, o, err)); // option where a value belongs
    EXPECT_EQ(err, "--config needs a value");
    EXPECT_FALSE(parse({"--gen-key", "a", "--pubkey", "b"}, o, err));
    EXPECT_FALSE(parse({"--force"}, o, err));
    EXPECT_EQ(err, "--force is only valid with --gen-key");
}
