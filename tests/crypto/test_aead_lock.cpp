// AeadLock<P>: counter -> nonce mapping (constraint C1) and cross-implementation wire
// compatibility (constraint C5: seal with implementation A, open with implementation B).
#include <gtest/gtest.h>

#include <random>
#include <type_traits>

#include "crypto/CipherRegistry.h"
#include "crypto/backends/AeadLock.h"
#include "crypto/backends/SodiumAead.h"
#if CPPVPN_WITH_OPENSSL
#include "crypto/backends/OpenSslAead.h"
#endif

using namespace crypto;

namespace
{

std::vector<uint8_t> randomBytes(size_t n, uint32_t seed)
{
    std::mt19937 rng(seed);
    std::vector<uint8_t> v(n);
    for (auto &b : v)
        b = static_cast<uint8_t>(rng());
    return v;
}

struct PrimitiveName
{
    template <class T>
    static std::string GetName(int) { return std::string(T::kAlgorithm) + "_" + T::kImpl; }
};

} // namespace

TEST(CounterNonce, ZeroPrefixThenLittleEndianCounter)
{
    uint8_t n[kNonceBytes];
    counterNonce(0x0102030405060708ull, n);
    const uint8_t expected[kNonceBytes] = {0, 0, 0, 0, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    EXPECT_EQ(0, std::memcmp(n, expected, kNonceBytes));

    counterNonce(0, n);
    EXPECT_EQ(std::vector<uint8_t>(n, n + kNonceBytes), std::vector<uint8_t>(kNonceBytes, 0));

    counterNonce(~0ull, n);
    EXPECT_EQ(std::vector<uint8_t>(n, n + 4), std::vector<uint8_t>(4, 0));
    EXPECT_EQ(std::vector<uint8_t>(n + 4, n + 12), std::vector<uint8_t>(8, 0xff));
}

// ---------------- AeadLock<P> == P with counterNonce(counter) ----------------

template <class P>
class AeadLockOver : public testing::Test {};
using AllPrimitives = testing::Types<SodiumChaCha20Poly1305, SodiumAes256Gcm
#if CPPVPN_WITH_OPENSSL
                                     , OpenSslChaCha20Poly1305, OpenSslAes256Gcm
#endif
                                     >;
TYPED_TEST_SUITE(AeadLockOver, AllPrimitives, PrimitiveName);

TYPED_TEST(AeadLockOver, SealUsesCounterNonceAndAppendsTag)
{
    if (std::is_same<TypeParam, SodiumAes256Gcm>::value && !sodiumAes256GcmAvailable())
        GTEST_SKIP() << "no hardware AES";
    const auto key = randomBytes(kKeyBytes, 1);
    const auto aad = randomBytes(14, 2);
    const auto pt = randomBytes(300, 3);
    const uint64_t counter = 0x00000001deadbeefull;

    AeadLock<TypeParam> lock(key.data());
    TypeParam prim(key.data());
    EXPECT_EQ(lock.overhead(), kTagBytes);

    uint8_t nonce[kNonceBytes];
    counterNonce(counter, nonce);
    std::vector<uint8_t> via_lock(pt.size() + kTagBytes), via_prim(pt.size() + kTagBytes);
    lock.seal(counter, aad.data(), aad.size(), pt.data(), pt.size(), via_lock.data());
    prim.seal(nonce, aad.data(), aad.size(), pt.data(), pt.size(), via_prim.data());
    EXPECT_EQ(via_lock, via_prim);

    std::vector<uint8_t> out(pt.size());
    ASSERT_TRUE(lock.open(counter, aad.data(), aad.size(), via_prim.data(), via_prim.size(), out.data()));
    EXPECT_EQ(out, pt);
}

TYPED_TEST(AeadLockOver, OpenRejectsShortInputWithoutCallingPrimitive)
{
    const auto key = randomBytes(kKeyBytes, 4);
    AeadLock<TypeParam> lock(key.data());
    uint8_t buf[kTagBytes] = {0}, out[kTagBytes];
    for (size_t len = 0; len < kTagBytes; len++)
        EXPECT_FALSE(lock.open(0, nullptr, 0, buf, len, out)) << "len " << len;
}

// ---------------- Cross-implementation (registry) ----------------

// For every algorithm with two or more registered implementations: identical ciphertext for
// identical inputs, and each implementation opens the other's output (design 01, section 2.1).
TEST(CrossImplementation, SameAlgorithmIsWireIdenticalAcrossLibraries)
{
    const auto &reg = CipherRegistry::instance();
    const auto key = randomBytes(kKeyBytes, 10);
    const auto aad = randomBytes(14, 11);
    int pairs = 0;

    for (uint8_t id : reg.algorithms())
    {
        std::vector<const CipherBackend *> impls;
        for (const auto &b : reg.all())
            if (b->algorithmId() == id)
                impls.push_back(b.get());

        for (const auto *a : impls)
            for (const auto *b : impls)
            {
                if (a == b)
                    continue;
                SCOPED_TRACE(std::string(a->algorithmName()) + ": " + a->implName() + " -> " +
                             b->implName());
                auto la = a->newLock(key.data());
                auto lb = b->newLock(key.data());
                for (size_t len : {size_t(0), size_t(1), size_t(15), size_t(16), size_t(1400)})
                {
                    const auto pt = randomBytes(len, static_cast<uint32_t>(len) + 20);
                    const uint64_t ctr = 1000 + len;
                    std::vector<uint8_t> ca(len + la->overhead()), cb(len + lb->overhead()), out(len);
                    la->seal(ctr, aad.data(), aad.size(), pt.data(), len, ca.data());
                    lb->seal(ctr, aad.data(), aad.size(), pt.data(), len, cb.data());
                    EXPECT_EQ(ca, cb) << "len " << len;
                    ASSERT_TRUE(lb->open(ctr, aad.data(), aad.size(), ca.data(), ca.size(), out.data()))
                        << "len " << len;
                    EXPECT_EQ(out, pt) << "len " << len;
                }
                pairs++;
            }
    }
    if (pairs == 0)
        GTEST_SKIP() << "only one implementation per algorithm registered (build with -DWITH_OPENSSL=ON)";
}
