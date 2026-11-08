// CipherRegistry: lookup by algorithm / implementation, duplicate handling, offer list.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>

#include "crypto/CipherRegistry.h"
#include "crypto/backends/XorBackend.h"

using namespace crypto;

namespace
{

// Second implementation of the xor algorithm, to model "same algorithm, other library".
class FakeXorImpl final : public CipherBackend
{
public:
    uint8_t algorithmId() const override { return kCipherXor; }
    const char *algorithmName() const override { return "xor"; }
    const char *implName() const override { return "fake"; }
    std::unique_ptr<SessionLock> newLock(const uint8_t key[kKeyBytes]) const override
    {
        return std::make_unique<XorLock>(key[0]);
    }
};

class FakeAlgo final : public CipherBackend
{
public:
    explicit FakeAlgo(uint8_t id) : id_(id) {}
    uint8_t algorithmId() const override { return id_; }
    const char *algorithmName() const override { return "fake-algo"; }
    const char *implName() const override { return "fake"; }
    std::unique_ptr<SessionLock> newLock(const uint8_t key[kKeyBytes]) const override
    {
        return std::make_unique<XorLock>(key[0]);
    }

private:
    uint8_t id_;
};

} // namespace

TEST(CipherRegistry, GlobalInstanceHasXorForProtocolV1)
{
    const CipherBackend *b = CipherRegistry::instance().find(kCipherXor);
    ASSERT_NE(b, nullptr);
    EXPECT_STREQ(b->implName(), "builtin");
    EXPECT_TRUE(b->insecure());
}

TEST(CipherRegistry, UnknownAlgorithmReturnsNull)
{
    EXPECT_EQ(CipherRegistry::instance().find(0xee), nullptr);
}

TEST(CipherRegistry, FindByImplementation)
{
    auto &r = CipherRegistry::instance();
    EXPECT_NE(r.find(kCipherXor, "builtin"), nullptr);
    EXPECT_EQ(r.find(kCipherXor, "openssl"), nullptr);
    EXPECT_EQ(r.find(kCipherXor, nullptr), nullptr);
}

TEST(CipherRegistry, RejectsDuplicateAndNull)
{
    CipherRegistry r;
    EXPECT_TRUE(r.add(std::make_unique<XorBackend>()));
    EXPECT_FALSE(r.add(std::make_unique<XorBackend>()));
    EXPECT_FALSE(r.add(nullptr));
    EXPECT_EQ(r.all().size(), 1u);
}

TEST(CipherRegistry, SameAlgorithmTwoImplementations)
{
    CipherRegistry r;
    ASSERT_TRUE(r.add(std::make_unique<XorBackend>()));
    ASSERT_TRUE(r.add(std::make_unique<FakeXorImpl>()));

    // Default lookup returns the first registered implementation
    EXPECT_STREQ(r.find(kCipherXor)->implName(), "builtin");
    EXPECT_STREQ(r.find(kCipherXor, "fake")->implName(), "fake");

    // The algorithm appears once in the offer list
    EXPECT_EQ(r.algorithms(), std::vector<uint8_t>{kCipherXor});
}

TEST(CipherRegistry, AlgorithmsInRegistrationOrder)
{
    CipherRegistry r;
    r.add(std::make_unique<FakeAlgo>(2));
    r.add(std::make_unique<XorBackend>());
    r.add(std::make_unique<FakeAlgo>(1));
    EXPECT_EQ(r.algorithms(), (std::vector<uint8_t>{2, 0, 1}));
}

// Same algorithm from two implementations must be wire-identical (design 01, section 2.1).
TEST(CipherRegistry, ImplementationsOfOneAlgorithmInteroperate)
{
    CipherRegistry r;
    r.add(std::make_unique<XorBackend>());
    r.add(std::make_unique<FakeXorImpl>());
    uint8_t key[kKeyBytes];
    expandV1XorKey(0x6b, key);

    auto a = r.find(kCipherXor, "builtin")->newLock(key);
    auto b = r.find(kCipherXor, "fake")->newLock(key);
    const uint8_t in[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t ct[16], pt[16];
    a->seal(0, nullptr, 0, in, 16, ct);
    ASSERT_TRUE(b->open(0, nullptr, 0, ct, 16, pt));
    EXPECT_EQ(0, std::memcmp(in, pt, 16));
}
