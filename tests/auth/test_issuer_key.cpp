// Passphrase-encrypted issuer key file (design 03 section 4).
#include <gtest/gtest.h>

#include <cstring>

#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>

#include "auth/IssuerKey.h"
#include "config/Ini.h"

using namespace auth;

namespace
{
class IssuerKeyFile : public testing::Test
{
protected:
    void SetUp() override
    {
        char tmpl[] = "/tmp/cppvpn_issuer_XXXXXX";
        ASSERT_NE(mkdtemp(tmpl), nullptr);
        dir_ = tmpl;
        path_ = dir_ + "/issuer.key";
    }
    void TearDown() override
    {
        unlink(path_.c_str());
        rmdir(dir_.c_str());
    }
    std::string dir_, path_;
};
} // namespace

TEST_F(IssuerKeyFile, EncryptedRoundTripWithOwnerOnlyMode)
{
    IssuerKey k;
    ASSERT_TRUE(generateIssuerKey(3, k));
    std::string err;
    ASSERT_TRUE(saveIssuerKey(path_, k, "correct horse battery", KdfStrength::kInteractive, err)) << err;
    struct stat st{};
    ASSERT_EQ(stat(path_.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600u);
    EXPECT_EQ(st.st_size, 149);

    std::string text;
    ASSERT_TRUE(config::readTextFile(path_, text, err));
    EXPECT_EQ(text.find(std::string(reinterpret_cast<const char *>(k.sk), 16)), std::string::npos)
        << "secret key bytes stored in the clear";

    IssuerKey l;
    ASSERT_TRUE(loadIssuerKey(path_, "correct horse battery", l, err)) << err;
    EXPECT_EQ(l.key_id, 3);
    EXPECT_EQ(0, std::memcmp(l.sk, k.sk, 64));
    EXPECT_EQ(0, std::memcmp(l.pk, k.pk, 32));
}

TEST_F(IssuerKeyFile, WrongPassphraseTamperingAndOverwrite)
{
    IssuerKey k, l;
    ASSERT_TRUE(generateIssuerKey(1, k));
    std::string err;
    ASSERT_TRUE(saveIssuerKey(path_, k, "passphrase-one", KdfStrength::kInteractive, err)) << err;
    EXPECT_FALSE(loadIssuerKey(path_, "passphrase-two", l, err));
    EXPECT_NE(err.find("wrong passphrase"), std::string::npos) << err;

    EXPECT_FALSE(saveIssuerKey(path_, k, "x", KdfStrength::kInteractive, err)) << "overwrote an issuer key";
    EXPECT_NE(err.find("never overwrite"), std::string::npos) << err;

    std::string text;
    ASSERT_TRUE(config::readTextFile(path_, text, err));
    for (size_t pos : {size_t(9) /* key_id in header */, size_t(40) /* salt */, text.size() - 1})
    {
        std::string bad = text;
        bad[pos] ^= 1;
        const std::string bad_path = dir_ + "/bad.key";
        std::ofstream(bad_path, std::ios::binary) << bad;
        EXPECT_FALSE(loadIssuerKey(bad_path, "passphrase-one", l, err)) << "byte " << pos;
        unlink(bad_path.c_str());
    }
    EXPECT_FALSE(loadIssuerKey(dir_ + "/missing", "x", l, err));
}
