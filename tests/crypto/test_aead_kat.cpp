// Known-answer tests (design 01, constraint C5): every AEAD primitive must reproduce published
// vectors byte for byte. These test the primitive with the vector's own nonce; the counter ->
// nonce mapping used on the wire is tested in test_aead_lock.cpp.
//
// Sources:
//   ChaCha20-Poly1305: RFC 8439 section 2.8.2 (AEAD example).
//     https://www.rfc-editor.org/rfc/rfc8439#section-2.8.2
//   AES-256-GCM: McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)", Appendix B,
//     test cases 13-16 (256-bit key, 96-bit IV): the GCM submission that NIST SP 800-38D
//     standardises (https://csrc.nist.gov/pubs/sp/800/38/d/final).
#include <gtest/gtest.h>

#include <type_traits>

#include "crypto/backends/SodiumAead.h"
#if CPPVPN_WITH_OPENSSL
#include "crypto/backends/OpenSslAead.h"
#endif
#include "hex.h"

using namespace crypto;

namespace
{

struct Vector
{
    const char *name;
    std::vector<uint8_t> key, nonce, aad, pt, ct, tag;
};

const Vector &rfc8439Vector()
{
    static const Vector v{
        "RFC8439_2_8_2",
        hex("80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f"
            "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f"),
        hex("07 00 00 00 40 41 42 43 44 45 46 47"),
        hex("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7"),
        bytesOf("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for "
                "the future, sunscreen would be it."),
        hex("d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2"
            "a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6"
            "3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b"
            "1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36"
            "92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58"
            "fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc"
            "3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b"
            "61 16"),
        hex("1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91"),
    };
    return v;
}

const std::vector<Vector> &gcmVectors()
{
    static const auto k15 = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    static const auto p15 = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                                "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    static const auto c15 = hex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                                "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad");
    static const std::vector<Vector> v{
        {"GCM_TC13_empty", std::vector<uint8_t>(32, 0), std::vector<uint8_t>(12, 0), {}, {}, {},
         hex("530f8afbc74536b9a963b4f1c4cb738b")},
        {"GCM_TC14_zero_block", std::vector<uint8_t>(32, 0), std::vector<uint8_t>(12, 0), {},
         std::vector<uint8_t>(16, 0), hex("cea7403d4d606b6e074ec5d3baf39d18"),
         hex("d0d1c8a799996bf0265b98b5d48ab919")},
        {"GCM_TC15_64B", k15, hex("cafebabefacedbaddecaf888"), {}, p15, c15,
         hex("b094dac5d93471bdec1a502270e3cc6c")},
        {"GCM_TC16_60B_with_aad", k15, hex("cafebabefacedbaddecaf888"),
         hex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
         std::vector<uint8_t>(p15.begin(), p15.begin() + 60),
         std::vector<uint8_t>(c15.begin(), c15.begin() + 60),
         hex("76fc6ece0f4e1768cddf8853bb2d551b")},
    };
    return v;
}

struct ImplName
{
    template <class T>
    static std::string GetName(int) { return T::kImpl; }
};

template <class P>
bool unavailable()
{
    return std::is_same<P, SodiumAes256Gcm>::value && !sodiumAes256GcmAvailable();
}

template <class P>
void checkVector(const Vector &v)
{
    SCOPED_TRACE(v.name);
    ASSERT_EQ(v.key.size(), kKeyBytes);
    ASSERT_EQ(v.nonce.size(), kNonceBytes);
    ASSERT_EQ(v.ct.size(), v.pt.size());
    P aead(v.key.data());

    std::vector<uint8_t> expected = v.ct;
    expected.insert(expected.end(), v.tag.begin(), v.tag.end());

    std::vector<uint8_t> sealed(v.pt.size() + kTagBytes);
    aead.seal(v.nonce.data(), v.aad.data(), v.aad.size(), v.pt.data(), v.pt.size(), sealed.data());
    EXPECT_EQ(sealed, expected) << "ciphertext || tag differs from the published vector";

    std::vector<uint8_t> opened(v.pt.size() + 1);
    ASSERT_TRUE(aead.open(v.nonce.data(), v.aad.data(), v.aad.size(), expected.data(),
                          expected.size(), opened.data()));
    opened.resize(v.pt.size());
    EXPECT_EQ(opened, v.pt);

    auto bad = expected;
    bad.back() ^= 0x80;
    EXPECT_FALSE(aead.open(v.nonce.data(), v.aad.data(), v.aad.size(), bad.data(), bad.size(),
                           opened.data()));
}

} // namespace

// ---------------- ChaCha20-Poly1305 ----------------

template <class P>
class ChaCha20Poly1305Kat : public testing::Test {};
using ChaChaImpls = testing::Types<SodiumChaCha20Poly1305
#if CPPVPN_WITH_OPENSSL
                                   , OpenSslChaCha20Poly1305
#endif
                                   >;
TYPED_TEST_SUITE(ChaCha20Poly1305Kat, ChaChaImpls, ImplName);

TYPED_TEST(ChaCha20Poly1305Kat, Rfc8439Section282)
{
    checkVector<TypeParam>(rfc8439Vector());
}

// ---------------- AES-256-GCM ----------------

template <class P>
class Aes256GcmKat : public testing::Test {};
using AesImpls = testing::Types<SodiumAes256Gcm
#if CPPVPN_WITH_OPENSSL
                                , OpenSslAes256Gcm
#endif
                                >;
TYPED_TEST_SUITE(Aes256GcmKat, AesImpls, ImplName);

TYPED_TEST(Aes256GcmKat, GcmSpecTestCases13To16)
{
    if (unavailable<TypeParam>())
        GTEST_SKIP() << "no hardware AES on this CPU (libsodium AES-256-GCM not registered)";
    for (const auto &v : gcmVectors())
        checkVector<TypeParam>(v);
}
