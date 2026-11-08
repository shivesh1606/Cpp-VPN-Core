// NodeConfig: defaults, precedence, validation (plan Discussion 4a, N2-N5).
#include <gtest/gtest.h>

#include <unistd.h>

#include <cstdlib>
#include <fstream>

#include "config/NodeConfig.h"
#include "crypto/backends/SodiumAead.h"
#include "net/ip/Cidr.h"

using namespace config;

namespace
{

class NodeConfigTest : public testing::Test
{
protected:
    void SetUp() override
    {
        char tmpl[] = "/tmp/cppvpn_cfg_XXXXXX";
        ASSERT_NE(mkdtemp(tmpl), nullptr);
        dir_ = tmpl;
    }
    void TearDown() override
    {
        unlink(path_.c_str());
        unlink(allowed_.c_str());
        rmdir(dir_.c_str());
    }
    // Writes `text` as the config file and loads it with `overrides`.
    NodeConfig load(const std::string &text, const std::vector<std::string> &overrides = {})
    {
        path_ = dir_ + "/node.conf";
        allowed_ = dir_ + "/allowed_clients";
        if (write_allowed_)
            std::ofstream(allowed_) << allowed_text_;
        std::ofstream(path_) << text << "\n[auth]\nallowed_clients = " << allowed_ << "\n";
        report_ = ConfigReport{};
        return loadNodeConfig(path_, overrides, report_);
    }
    std::string allErrors() const
    {
        std::string s;
        for (const auto &e : report_.errors)
            s += e + "\n";
        return s;
    }
    bool hasError(const std::string &needle) const
    {
        return allErrors().find(needle) != std::string::npos;
    }
    bool hasWarning(const std::string &needle) const
    {
        for (const auto &w : report_.warnings)
            if (w.find(needle) != std::string::npos)
                return true;
        return false;
    }

    std::string dir_, path_, allowed_;
    std::string allowed_text_;
    bool write_allowed_ = true;
    ConfigReport report_;
};

} // namespace

// Acceptance criterion of M3: without a config file the server behaves exactly as before.
TEST(NodeConfigDefaults, MatchThePreM3Constants)
{
    ConfigReport r;
    const NodeConfig c = loadNodeConfig("", {}, r);
    EXPECT_TRUE(r.ok());
    EXPECT_TRUE(r.warnings.empty());
    EXPECT_FALSE(c.from_file);
    EXPECT_EQ(c.port, 5555);               // was SocketManager::createUdpSocket(5555)
    EXPECT_EQ(c.tun_name, "tun0");         // was TunDevice::create("tun0")
    EXPECT_EQ(net::ipv4ToString(c.pool_start), "10.8.0.2"); // was ClientManager cm(100, "10.8.0.2")
    EXPECT_EQ(c.pool_size, 100u);
    EXPECT_EQ(c.pending_expiry_s, 10);     // was HANDSHAKE_TIMEOUT
    EXPECT_EQ(c.dead_after_s, 60);         // was CLIENT_DEAD_TIMEOUT
    EXPECT_FALSE(c.configure_tun);         // tun0 address set outside the server, as before
    EXPECT_TRUE(c.node_key.empty());       // no identity required without a config file
    EXPECT_EQ(c.auth_mode, "allowlist"); // protocol v2 needs a config file (node key) anyway
    EXPECT_TRUE(c.accept_v1);
    EXPECT_EQ(c.keepalive_s, 15);
}

TEST_F(NodeConfigTest, FileValuesApplyAndNodeKeyDefaults)
{
    const NodeConfig c = load("[node]\nid = in-1\nport = 6000\n[timers]\npending_expiry_s = 5\n");
    ASSERT_TRUE(report_.ok()) << allErrors();
    EXPECT_TRUE(c.from_file);
    EXPECT_EQ(c.source, path_);
    EXPECT_EQ(c.id, "in-1");
    EXPECT_EQ(c.port, 6000);
    EXPECT_EQ(c.pending_expiry_s, 5);
    EXPECT_EQ(c.node_key, kDefaultNodeKeyPath); // a config file implies a node identity (N1)
}

TEST_F(NodeConfigTest, TunCidrMakesServerConfigureTunAndDerivesPool)
{
    const NodeConfig c = load("[tunnel]\ntun_name = vpn7\ntun_cidr = 10.9.0.1/24\nmtu = 1400\n");
    ASSERT_TRUE(report_.ok()) << allErrors();
    EXPECT_TRUE(c.configure_tun);
    EXPECT_EQ(c.tun_name, "vpn7");
    EXPECT_EQ(net::ipv4ToString(c.tun_addr), "10.9.0.1");
    EXPECT_EQ(c.tun_prefix, 24);
    EXPECT_EQ(c.mtu, 1400);
    EXPECT_EQ(net::ipv4ToString(c.pool_start), "10.9.0.2");
    EXPECT_EQ(c.pool_size, 253u);
}

TEST_F(NodeConfigTest, OverridesBeatTheFile)
{
    const NodeConfig c = load("[node]\nport = 6000\n", {"node.port=7000", "tunnel.tun_cidr=10.7.0.1/28"});
    ASSERT_TRUE(report_.ok()) << allErrors();
    EXPECT_EQ(c.port, 7000);
    EXPECT_EQ(c.pool_size, 13u);
}

TEST(NodeConfigOverrides, WorkWithoutAFileAndReportSource)
{
    ConfigReport r;
    const NodeConfig c = loadNodeConfig("", {"node.port=0"}, r);
    ASSERT_EQ(r.errors.size(), 1u);
    EXPECT_EQ(r.errors[0], "--set: node.port: expected an integer in 1..65535, got '0'");
    EXPECT_TRUE(c.node_key.empty());

    std::string s, k, v, err;
    ASSERT_TRUE(parseOverride("crypto.impl.aes256gcm=openssl", s, k, v, err));
    EXPECT_EQ(s, "crypto");
    EXPECT_EQ(k, "impl.aes256gcm");
    EXPECT_EQ(v, "openssl");
    EXPECT_FALSE(parseOverride("port=1", s, k, v, err));
    EXPECT_FALSE(parseOverride("node.port", s, k, v, err));
}

TEST_F(NodeConfigTest, UnknownSectionsAndKeysAreErrorsWithLineNumbers)
{
    load("[node]\nprot = 5555\n[tunel]\nmtu = 1400\n");
    EXPECT_TRUE(hasError("line 2: node.prot: unknown key")) << allErrors();
    EXPECT_TRUE(hasError("line 4: tunel.mtu: unknown section [tunel]")) << allErrors();
}

TEST_F(NodeConfigTest, InvalidValues)
{
    load("[node]\nport = 99999\ntags = ok, bad tag\n[tunnel]\nmtu = 100\ntun_cidr = 10.8.0.1/8\n"
         "tun_name = this-name-is-too-long\n[timers]\npending_expiry_s = 0\n");
    EXPECT_TRUE(hasError("line 2: node.port: expected an integer in 1..65535, got '99999'")) << allErrors();
    EXPECT_TRUE(hasError("node.tags: invalid tag 'bad tag'"));
    EXPECT_TRUE(hasError("tunnel.mtu: expected an integer in 576..1500"));
    EXPECT_TRUE(hasError("tunnel.tun_cidr: prefix /8 not supported"));
    EXPECT_TRUE(hasError("tunnel.tun_name: expected 1-15 characters"));
    EXPECT_TRUE(hasError("timers.pending_expiry_s: expected an integer in 1..300"));
}

TEST_F(NodeConfigTest, TunCidrWithNoClientAddressesIsRejected)
{
    load("[tunnel]\ntun_cidr = 10.8.0.254/24\n");
    EXPECT_TRUE(hasError("no client addresses left after 10.8.0.254")) << allErrors();
}

// The config must never claim protection the binary does not implement, nor run without client
// authentication by accident.
TEST_F(NodeConfigTest, AuthModes)
{
    load("[auth]\nmode = allowlist\n");
    EXPECT_TRUE(report_.ok()) << allErrors();
    load("[auth]\nmode = open\n");
    EXPECT_EQ(report_.ok(), bool(CPPVPN_ALLOW_OPEN_AUTH)) << allErrors();
    if (!CPPVPN_ALLOW_OPEN_AUTH)
    {
        EXPECT_TRUE(hasError("needs a build with -DALLOW_OPEN_AUTH=ON")) << allErrors();
    }
    load("[auth]\nmode = ticket\n");
    EXPECT_TRUE(hasError("'ticket' needs tickets (milestone M5)"));
    load("[auth]\nmode = none\n");
    EXPECT_TRUE(hasError("expected open | allowlist | ticket"));
}

TEST_F(NodeConfigTest, AllowedClientsFile)
{
    const std::string k1(43, 'A'), k2 = std::string(42, 'A') + "E"; // two valid 32-byte keys
    allowed_text_ = "# clients of this node\n" + k1 + "  laptop   # Windows\n\n" + k2 + "\r\n";
    NodeConfig c = load("[node]\nid = n1\n");
    ASSERT_TRUE(report_.ok()) << allErrors();
    ASSERT_EQ(c.allowed_keys.size(), 2u);
    EXPECT_EQ(c.allowed_names.at(c.allowed_keys[0]), "laptop");
    EXPECT_EQ(c.allowed_names.at(c.allowed_keys[1]), k2.substr(0, 8)); // no name: key prefix
    EXPECT_NE(describe(c).find("2 clients from"), std::string::npos);

    allowed_text_ = k1 + "\nnot-a-key\n" + k1 + "\n";
    load("[node]\nid = n1\n");
    EXPECT_TRUE(hasError("allowed_clients:2: not a client public key")) << allErrors();
    EXPECT_TRUE(hasError("allowed_clients:3: duplicate key"));

    allowed_text_ = "# nobody yet\n";
    load("[node]\nid = n1\n");
    EXPECT_TRUE(report_.ok());
    EXPECT_TRUE(hasWarning("no clients listed"));

    write_allowed_ = false;
    unlink((dir_ + "/allowed_clients").c_str());
    load("[node]\nid = n1\n");
    EXPECT_TRUE(hasError("auth.allowed_clients: cannot open")) << allErrors();
}

TEST_F(NodeConfigTest, V1SwitchAndKeepalive)
{
    NodeConfig c = load("[node]\naccept_v1 = false\n[timers]\nkeepalive_s = 0\n");
    ASSERT_TRUE(report_.ok()) << allErrors();
    EXPECT_FALSE(c.accept_v1);
    EXPECT_EQ(c.keepalive_s, 0);
    load("[timers]\nkeepalive_s = 301\n");
    EXPECT_TRUE(hasError("timers.keepalive_s: expected an integer in 0..300"));
}

TEST_F(NodeConfigTest, CryptoIsValidatedAgainstTheRegistry)
{
    allowed_text_ = std::string(43, 'A') + "\n"; // one client, so no "empty allowlist" warning
    const NodeConfig c = load("[crypto]\nalgorithms = chacha20poly1305\nimpl.chacha20poly1305 = libsodium\n");
    ASSERT_TRUE(report_.ok()) << allErrors();
    EXPECT_EQ(c.algorithms, std::vector<std::string>{"chacha20poly1305"});
    EXPECT_EQ(c.impl.at("chacha20poly1305"), "libsodium");
    EXPECT_TRUE(report_.warnings.empty()) << "crypto keys are live since M4";

    load("[crypto]\nalgorithms = chacha20poly1305, rot13\n");
    EXPECT_TRUE(hasError("unknown algorithm 'rot13'")) << allErrors();
    load("[crypto]\nimpl.chacha20poly1305 = wolfssl\n");
    EXPECT_TRUE(hasError("implementation 'wolfssl' of chacha20poly1305 is not in this binary"));
    load("[crypto]\nimpl.chacha20poly1305 = openssl\n");
    EXPECT_EQ(report_.ok(), bool(CPPVPN_WITH_OPENSSL)) << allErrors();
}

TEST_F(NodeConfigTest, XorNeedsExplicitInsecureOptIn)
{
    load("[crypto]\nalgorithms = chacha20poly1305, xor\n");
    EXPECT_TRUE(hasError("'xor' is insecure")) << allErrors();
    load("[crypto]\nalgorithms = chacha20poly1305, xor\nallow_insecure_xor = true\n");
    EXPECT_TRUE(report_.ok()) << allErrors();
    load("[crypto]\nallow_insecure_xor = maybe\n");
    EXPECT_TRUE(hasError("expected true or false"));
}

TEST_F(NodeConfigTest, RejectAfterMustExceedRekeyAfter)
{
    load("[timers]\nrekey_after_s = 120\nreject_after_s = 120\n");
    EXPECT_TRUE(hasError("reject_after_s (120) must be greater than rekey_after_s (120)")) << allErrors();
}

TEST_F(NodeConfigTest, IssuerKeysAndRevocationUrl)
{
    // 32 zero bytes in base64url = 43 'A'
    load("[auth]\nissuer_pk.1 = " + std::string(43, 'A') +
         "\nrevocation_url = https://example.org/r.bin\n");
    EXPECT_TRUE(report_.ok()) << allErrors();
    EXPECT_TRUE(hasWarning("not used until tickets (milestone M5)"));
    load("[auth]\nissuer_pk.0 = " + std::string(43, 'A') + "\nissuer_pk.2 = short\n"
         "revocation_url = http://insecure/r.bin\n");
    EXPECT_TRUE(hasError("auth.issuer_pk.0: key id must be 1..255")) << allErrors();
    EXPECT_TRUE(hasError("auth.issuer_pk.2: expected a 32-byte Ed25519 public key"));
    EXPECT_TRUE(hasError("auth.revocation_url: must be an https:// URL"));
}

TEST_F(NodeConfigTest, SyntaxErrorAndMissingFile)
{
    load("[node]\nport\n");
    EXPECT_TRUE(hasError("node.conf: line 2: expected 'key = value'")) << allErrors();
    ConfigReport r;
    loadNodeConfig(dir_ + "/missing.conf", {}, r);
    ASSERT_EQ(r.errors.size(), 1u);
    EXPECT_EQ(r.errors[0], "cannot open " + dir_ + "/missing.conf");
}

// The documented reference config must stay valid as the schema evolves.
TEST(NodeConfigExample, DeployExampleIsValid)
{
    char tmpl[] = "/tmp/cppvpn_allowed_XXXXXX";
    const int fd = mkstemp(tmpl); // the example points at /etc/cppvpn/allowed_clients
    ASSERT_GE(fd, 0);
    close(fd);
    ConfigReport r;
    const NodeConfig c = loadNodeConfig(std::string(CPPVPN_SOURCE_DIR) + "/deploy/node.conf.example",
                                        {std::string("auth.allowed_clients=") + tmpl}, r);
    unlink(tmpl);
    std::string errs;
    for (const auto &e : r.errors)
        errs += e + "\n";
    EXPECT_TRUE(r.ok()) << errs;
    EXPECT_TRUE(c.configure_tun);
    EXPECT_EQ(c.pool_size, 253u);
    EXPECT_FALSE(describe(c).empty());
}
