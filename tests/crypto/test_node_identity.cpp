// NodeIdentity: --gen-key / key loading (plan decision N1).
#include <gtest/gtest.h>

#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <fstream>

#include "config/Ini.h"
#include "crypto/NodeIdentity.h"

using namespace crypto;

namespace
{

class NodeIdentityTest : public testing::Test
{
protected:
    void SetUp() override
    {
        char tmpl[] = "/tmp/cppvpn_key_XXXXXX";
        ASSERT_NE(mkdtemp(tmpl), nullptr);
        dir_ = tmpl;
        key_ = dir_ + "/node.key";
    }
    void TearDown() override
    {
        unlink(key_.c_str());
        unlink((key_ + ".tmp").c_str());
        rmdir(dir_.c_str());
    }
    std::string dir_, key_;
};

} // namespace

TEST(Base64Url, RoundTripNoPaddingUrlAlphabet)
{
    const uint8_t data[32] = {0xfb, 0xff, 0xfe, 1, 2, 3}; // 0xfb 0xff -> "-_" in base64url
    const std::string s = toBase64Url(data, sizeof(data));
    EXPECT_EQ(s.size(), 43u);
    EXPECT_EQ(s.find_first_of("+/="), std::string::npos);
    EXPECT_EQ(s.substr(0, 4), "-__-");
    uint8_t back[32];
    ASSERT_TRUE(fromBase64Url(s, back, sizeof(back)));
    EXPECT_EQ(0, std::memcmp(data, back, 32));
    EXPECT_FALSE(fromBase64Url(s + "A", back, sizeof(back)));      // wrong length
    EXPECT_FALSE(fromBase64Url(s.substr(0, 42), back, sizeof(back)));
    EXPECT_FALSE(fromBase64Url(std::string(42, 'A') + "+", back, sizeof(back))); // std alphabet
}

TEST_F(NodeIdentityTest, GenerateWritesOwnerOnlyFileAndLoadsBack)
{
    NodeIdentity gen;
    std::string err;
    ASSERT_TRUE(generateNodeKey(key_, false, gen, err)) << err;
    ASSERT_TRUE(gen.loaded());

    struct stat st{};
    ASSERT_EQ(stat(key_.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600u);
    EXPECT_NE(access((key_ + ".tmp").c_str(), F_OK), 0) << "temporary file left behind";

    std::string text;
    ASSERT_TRUE(config::readTextFile(key_, text, err));
    EXPECT_EQ(text.size(), 44u); // 43 base64url characters + '\n'

    NodeIdentity loaded;
    ASSERT_TRUE(loadNodeKey(key_, loaded, err)) << err;
    EXPECT_EQ(loaded.publicKeyBase64Url(), gen.publicKeyBase64Url());
    EXPECT_EQ(0, std::memcmp(loaded.privateKey(), gen.privateKey(), kX25519Bytes));

    // The public key is X25519(sk, basepoint)
    uint8_t pk[kX25519Bytes];
    ASSERT_EQ(crypto_scalarmult_base(pk, loaded.privateKey()), 0);
    EXPECT_EQ(0, std::memcmp(pk, loaded.publicKey(), kX25519Bytes));
}

TEST_F(NodeIdentityTest, RefusesToReplaceExistingKeyUnlessForced)
{
    NodeIdentity a, b, c;
    std::string err;
    ASSERT_TRUE(generateNodeKey(key_, false, a, err)) << err;
    EXPECT_FALSE(generateNodeKey(key_, false, b, err));
    EXPECT_NE(err.find("already exists"), std::string::npos);
    ASSERT_TRUE(generateNodeKey(key_, true, c, err)) << err;
    EXPECT_NE(c.publicKeyBase64Url(), a.publicKeyBase64Url()); // new identity
}

TEST_F(NodeIdentityTest, RefusesKeyReadableByOthers)
{
    NodeIdentity gen, loaded;
    std::string err;
    ASSERT_TRUE(generateNodeKey(key_, false, gen, err));
    ASSERT_EQ(chmod(key_.c_str(), 0644), 0);
    EXPECT_FALSE(loadNodeKey(key_, loaded, err));
    EXPECT_NE(err.find("has mode 0644"), std::string::npos) << err;
    EXPECT_FALSE(loaded.loaded());
}

TEST_F(NodeIdentityTest, RejectsMissingDirectoryAndMalformedFiles)
{
    NodeIdentity id;
    std::string err;
    EXPECT_FALSE(loadNodeKey(key_, id, err));
    EXPECT_NE(err.find("--gen-key"), std::string::npos) << err; // tells the operator what to do

    for (const std::string &content : {std::string("not-a-key\n"), std::string(43, 'A') + "B\n",
                                       std::string("")})
    {
        { std::ofstream(key_) << content; }
        ASSERT_EQ(chmod(key_.c_str(), 0600), 0);
        EXPECT_FALSE(loadNodeKey(key_, id, err)) << "content: " << content;
        EXPECT_NE(err.find("is not a node key"), std::string::npos) << err;
    }

    EXPECT_FALSE(loadNodeKey(dir_, id, err)); // a directory
    EXPECT_NE(err.find("not a regular file"), std::string::npos) << err;

    NodeIdentity gen;
    EXPECT_FALSE(generateNodeKey(dir_ + "/no/such/dir/key", false, gen, err));
}
