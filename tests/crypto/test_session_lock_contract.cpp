// SessionLock contract, run against EVERY backend in the global CipherRegistry.
// New backends (M2: libsodium ChaCha20-Poly1305 / AES-256-GCM, optional OpenSSL) are covered
// automatically once registered. AEAD-only checks are skipped for overhead() == 0 (xor).
#include <gtest/gtest.h>

#include <cctype>
#include <random>
#include <string>
#include <vector>

#include "crypto/CipherRegistry.h"

using namespace crypto;

namespace
{

std::vector<const CipherBackend *> registeredBackends()
{
    std::vector<const CipherBackend *> v;
    for (const auto &b : CipherRegistry::instance().all())
        v.push_back(b.get());
    return v;
}

std::string backendName(const testing::TestParamInfo<const CipherBackend *> &info)
{
    std::string n = std::string(info.param->algorithmName()) + "_" + info.param->implName();
    for (auto &c : n)
        if (!isalnum(static_cast<unsigned char>(c)))
            c = '_';
    return n;
}

std::vector<uint8_t> bytes(size_t n, uint32_t seed)
{
    std::mt19937 rng(seed);
    std::vector<uint8_t> v(n);
    for (auto &b : v)
        b = static_cast<uint8_t>(rng());
    return v;
}

class SessionLockContract : public testing::TestWithParam<const CipherBackend *>
{
protected:
    void SetUp() override
    {
        key_ = bytes(kKeyBytes, 99);
        lock_ = GetParam()->newLock(key_.data());
        ASSERT_NE(lock_, nullptr);
    }
    std::vector<uint8_t> key_;
    std::unique_ptr<SessionLock> lock_;
};

} // namespace

TEST_P(SessionLockContract, RoundTripWithCounterAndAad)
{
    const auto aad = bytes(14, 5); // v2 transport header size
    for (size_t len : {size_t(0), size_t(1), size_t(64), size_t(512), size_t(1400)})
    {
        const auto pt = bytes(len, static_cast<uint32_t>(len));
        std::vector<uint8_t> ct(len + lock_->overhead()), out(len);
        lock_->seal(42, aad.data(), aad.size(), pt.data(), len, ct.data());
        ASSERT_TRUE(lock_->open(42, aad.data(), aad.size(), ct.data(), ct.size(), out.data()))
            << "len " << len;
        EXPECT_EQ(out, pt) << "len " << len;
    }
}

TEST_P(SessionLockContract, SameKeyNewLockInteroperates)
{
    auto other = GetParam()->newLock(key_.data());
    const auto pt = bytes(100, 1);
    std::vector<uint8_t> ct(pt.size() + lock_->overhead()), out(pt.size());
    lock_->seal(7, nullptr, 0, pt.data(), pt.size(), ct.data());
    ASSERT_TRUE(other->open(7, nullptr, 0, ct.data(), ct.size(), out.data()));
    EXPECT_EQ(out, pt);
}

TEST_P(SessionLockContract, AeadRejectsTamperedCiphertextTagAadAndCounter)
{
    if (lock_->overhead() == 0)
        GTEST_SKIP() << GetParam()->algorithmName() << " has no integrity (insecure baseline)";

    const auto aad = bytes(14, 8);
    const auto pt = bytes(200, 9);
    std::vector<uint8_t> ct(pt.size() + lock_->overhead()), out(pt.size());
    lock_->seal(1, aad.data(), aad.size(), pt.data(), pt.size(), ct.data());

    auto bad = ct;
    bad[0] ^= 1; // ciphertext
    EXPECT_FALSE(lock_->open(1, aad.data(), aad.size(), bad.data(), bad.size(), out.data()));
    bad = ct;
    bad.back() ^= 1; // tag
    EXPECT_FALSE(lock_->open(1, aad.data(), aad.size(), bad.data(), bad.size(), out.data()));
    auto bad_aad = aad;
    bad_aad[0] ^= 1; // header
    EXPECT_FALSE(lock_->open(1, bad_aad.data(), bad_aad.size(), ct.data(), ct.size(), out.data()));
    EXPECT_FALSE(lock_->open(2, aad.data(), aad.size(), ct.data(), ct.size(), out.data())); // counter
}

TEST_P(SessionLockContract, AeadRejectsInputShorterThanTag)
{
    if (lock_->overhead() == 0)
        GTEST_SKIP() << "no tag";
    std::vector<uint8_t> tiny(lock_->overhead() - 1), out(1);
    EXPECT_FALSE(lock_->open(0, nullptr, 0, tiny.data(), tiny.size(), out.data()));
}

INSTANTIATE_TEST_SUITE_P(AllRegisteredBackends, SessionLockContract,
                         testing::ValuesIn(registeredBackends()), backendName);
