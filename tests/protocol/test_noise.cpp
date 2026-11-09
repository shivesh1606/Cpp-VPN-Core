// Noise_IK_25519_ChaChaPoly_BLAKE2b (design 02 section 2, D1; verification section 10.1).
//
// - HMAC/HKDF-BLAKE2b against values computed independently with Python's hmac + hashlib.blake2b
// - the full IK handshake + transport messages against two published vector sets
//   (cacophony, snow): tests/protocol/vectors/noise_ik_25519_chachapoly_blake2b.txt
// - negative cases: tampering, low-order ephemeral, wrong responder key
#include <gtest/gtest.h>

#include <sodium.h>

#include <cstring>

#include "config/Ini.h"
#include "protocol/noise/Noise.h"
#include "../crypto/hex.h"

using namespace noise;

namespace
{
std::string toHex(const uint8_t *p, size_t n)
{
    static const char *d = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++)
        s += {d[p[i] >> 4], d[p[i] & 15]};
    return s;
}
std::vector<uint8_t> pubOf(const std::vector<uint8_t> &priv)
{
    std::vector<uint8_t> pub(kDhLen);
    EXPECT_TRUE(publicKey(priv.data(), pub.data()));
    return pub;
}
} // namespace

// ---------------- HMAC / HKDF (Noise section 4.3) ----------------

TEST(NoiseHmac, MatchesPythonHmacBlake2b)
{
    uint8_t out[kHashLen];
    const std::string msg = "The quick brown fox jumps over the lazy dog";
    hmac(reinterpret_cast<const uint8_t *>("key"), 3, reinterpret_cast<const uint8_t *>(msg.data()),
         msg.size(), nullptr, 0, out);
    EXPECT_EQ(toHex(out, kHashLen),
              "92294f92c0dfb9b00ec9ae8bd94d7e7d8a036b885a499f149dfe2fd2199394aaaf6b8894a1730cccb2cd050f9bcf5062a38b51b0dab33207f8ef35ae2c9df51b");

    std::vector<uint8_t> long_key(200); // longer than the 128-byte block: hashed first
    for (size_t i = 0; i < long_key.size(); i++)
        long_key[i] = static_cast<uint8_t>(i);
    hmac(long_key.data(), long_key.size(), reinterpret_cast<const uint8_t *>("abc"), 3, nullptr, 0, out);
    EXPECT_EQ(toHex(out, kHashLen),
              "feb09eb5b1c557085c0a53bdf39ef7bc9af291f21d7c917cd1cf09542aab95362de79b3925fe55d92997423b5a68be1bda2f6518df34fa1053bb3ef559b08200");

    hmac(nullptr, 0, nullptr, 0, nullptr, 0, out);
    EXPECT_EQ(toHex(out, kHashLen),
              "198cd2006f66ff83fbbd913f78aca2251caf4f19fe9475aade8cf2091b99a68466775177424f58286886cbae8229644cec747237d4b721735485e17372fdf59c");

    // Two-part input equals the concatenation
    uint8_t a[kHashLen];
    hmac(reinterpret_cast<const uint8_t *>("key"), 3, reinterpret_cast<const uint8_t *>("The quick "), 10,
         reinterpret_cast<const uint8_t *>(msg.data() + 10), msg.size() - 10, a);
    hmac(reinterpret_cast<const uint8_t *>("key"), 3, reinterpret_cast<const uint8_t *>(msg.data()),
         msg.size(), nullptr, 0, out);
    EXPECT_EQ(0, std::memcmp(a, out, kHashLen));
}

TEST(NoiseHkdf, ThreeOutputsMatchPython)
{
    uint8_t ck[kHashLen], ikm[32], o1[kHashLen], o2[kHashLen], o3[kHashLen];
    for (int i = 0; i < 64; i++)
        ck[i] = static_cast<uint8_t>(i);
    for (int i = 0; i < 32; i++)
        ikm[i] = static_cast<uint8_t>(100 + i);
    hkdf(ck, ikm, sizeof(ikm), o1, o2, o3);
    EXPECT_EQ(toHex(o1, kHashLen), "2262ed5f40c3324574d00a1e0849a7cc67fb5b6a80211c3c59404bb8e47512b1cb95e73840718c5d68ca345f934f39a52f1f31e8f6d3ed521f0664f46feddae4");
    EXPECT_EQ(toHex(o2, kHashLen), "f6a6559fa2aaab64d3d2666b83fe3f4fed6fae1959537fedd6a39b6f8d411e6132593234cc2a750244335da5021c27bf7eacbb65cfa608457de6ecc144b90077");
    EXPECT_EQ(toHex(o3, kHashLen), "07c82c1301c70e885f4662f1f3f7b7bb9e04d81c94a6e1882f812c02ffb69580c93095bb599ad2fced3d3cf38c9c17df4fb3c0029f231247fca69b040e16449e");
}

// ---------------- Published vectors ----------------

class NoiseVectors : public testing::TestWithParam<std::string>
{
protected:
    static const config::IniFile &file()
    {
        static config::IniFile ini = [] {
            config::IniFile f;
            std::string text, err;
            EXPECT_TRUE(config::readTextFile(std::string(CPPVPN_SOURCE_DIR) +
                                                 "/tests/protocol/vectors/noise_ik_25519_chachapoly_blake2b.txt",
                                             text, err))
                << err;
            EXPECT_TRUE(f.parse(text, err)) << err;
            return f;
        }();
        return ini;
    }
    std::vector<uint8_t> field(const std::string &key) const
    {
        const auto *e = file().get(GetParam(), key);
        return e ? hex(e->value) : std::vector<uint8_t>{};
    }
    bool has(const std::string &key) const { return file().get(GetParam(), key) != nullptr; }
};

TEST_P(NoiseVectors, HandshakeAndTransportMatchByteForByte)
{
    ASSERT_TRUE(has("init_static")) << "vector " << GetParam() << " missing";
    const auto init_s = field("init_static"), init_e = field("init_ephemeral");
    const auto resp_s = field("resp_static"), resp_e = field("resp_ephemeral");
    const auto rs = field("init_remote_static");
    const auto ip = field("init_prologue"), rp = field("resp_prologue");
    ASSERT_EQ(rs, pubOf(resp_s));

    HandshakeIK I, R;
    ASSERT_TRUE(I.initInitiator(init_s.data(), rs.data(), ip.data(), ip.size()));
    ASSERT_TRUE(R.initResponder(resp_s.data(), rp.data(), rp.size()));
    I.setEphemeral(init_e.data());
    R.setEphemeral(resp_e.data());

    uint8_t buf[1024], pt[1024];
    size_t n = 0, m = 0;

    // msg0: -> e, es, s, ss
    const auto p0 = field("msg0.payload"), c0 = field("msg0.ciphertext");
    ASSERT_TRUE(I.writeMessage1(p0.data(), p0.size(), buf, n));
    EXPECT_EQ(std::vector<uint8_t>(buf, buf + n), c0) << "msg0";
    ASSERT_TRUE(R.readMessage1(c0.data(), c0.size(), pt, m));
    EXPECT_EQ(std::vector<uint8_t>(pt, pt + m), p0);
    EXPECT_EQ(std::vector<uint8_t>(R.remoteStatic(), R.remoteStatic() + kDhLen), pubOf(init_s));

    // msg1: <- e, ee, se
    const auto p1 = field("msg1.payload"), c1 = field("msg1.ciphertext");
    ASSERT_TRUE(R.writeMessage2(p1.data(), p1.size(), buf, n));
    EXPECT_EQ(std::vector<uint8_t>(buf, buf + n), c1) << "msg1";
    ASSERT_TRUE(I.readMessage2(c1.data(), c1.size(), pt, m));
    EXPECT_EQ(std::vector<uint8_t>(pt, pt + m), p1);

    EXPECT_EQ(0, std::memcmp(I.handshakeHash(), R.handshakeHash(), kHashLen));
    if (has("handshake_hash"))
    {
        EXPECT_EQ(std::vector<uint8_t>(I.handshakeHash(), I.handshakeHash() + kHashLen),
                  field("handshake_hash"));
    }

    // Transport: messages alternate direction, implicit nonces from Split()
    CipherState i_send, i_recv, r_recv, r_send;
    I.split(i_send, i_recv);
    R.split(r_recv, r_send);
    int transport = 0;
    for (int i = 2; has("msg" + std::to_string(i) + ".payload"); i++, transport++)
    {
        const auto p = field("msg" + std::to_string(i) + ".payload");
        const auto c = field("msg" + std::to_string(i) + ".ciphertext");
        CipherState &tx = (i % 2 == 0) ? i_send : r_send;
        CipherState &rx = (i % 2 == 0) ? r_recv : i_recv;
        n = tx.encryptWithAd(nullptr, 0, p.data(), p.size(), buf);
        EXPECT_EQ(std::vector<uint8_t>(buf, buf + n), c) << "msg" << i;
        ASSERT_TRUE(rx.decryptWithAd(nullptr, 0, c.data(), c.size(), pt, m)) << "msg" << i;
        EXPECT_EQ(std::vector<uint8_t>(pt, pt + m), p);
    }
    EXPECT_GE(transport, 2);
}

INSTANTIATE_TEST_SUITE_P(Published, NoiseVectors, testing::Values("cacophony", "snow"));

// ---------------- Negative cases ----------------

namespace
{
struct Pair
{
    uint8_t is[kDhLen], rs[kDhLen], rs_pub[kDhLen];
    Pair()
    {
        randombytes_buf(is, kDhLen);
        randombytes_buf(rs, kDhLen);
        publicKey(rs, rs_pub);
    }
};
const uint8_t kPrologue[] = "cppvpn-v2";
} // namespace

TEST(NoiseIK, TamperedMessage1IsRejectedAnywhere)
{
    Pair k;
    HandshakeIK I0;
    ASSERT_TRUE(I0.initInitiator(k.is, k.rs_pub, kPrologue, 9));
    uint8_t msg[256], pt[256];
    size_t n = 0, m = 0;
    const uint8_t payload[17] = {1, 2, 3};
    ASSERT_TRUE(I0.writeMessage1(payload, sizeof(payload), msg, n));
    ASSERT_EQ(n, HandshakeIK::kMsg1Overhead + sizeof(payload));
    for (size_t pos : {size_t(0), size_t(40), n - 1})
    {
        HandshakeIK R;
        ASSERT_TRUE(R.initResponder(k.rs, kPrologue, 9));
        std::vector<uint8_t> bad(msg, msg + n);
        bad[pos] ^= 1;
        EXPECT_FALSE(R.readMessage1(bad.data(), bad.size(), pt, m)) << "byte " << pos;
    }
    HandshakeIK R;
    ASSERT_TRUE(R.initResponder(k.rs, kPrologue, 9));
    EXPECT_FALSE(R.readMessage1(msg, HandshakeIK::kMsg1Overhead - 1, pt, m)) << "short";
}

TEST(NoiseIK, PrologueAndResponderKeyAreBound)
{
    Pair k, other;
    HandshakeIK I;
    ASSERT_TRUE(I.initInitiator(k.is, k.rs_pub, kPrologue, 9));
    uint8_t msg[256], pt[256];
    size_t n = 0, m = 0;
    ASSERT_TRUE(I.writeMessage1(nullptr, 0, msg, n));

    HandshakeIK wrong_prologue, wrong_key;
    ASSERT_TRUE(wrong_prologue.initResponder(k.rs, reinterpret_cast<const uint8_t *>("cppvpn-v3"), 9));
    EXPECT_FALSE(wrong_prologue.readMessage1(msg, n, pt, m));
    ASSERT_TRUE(wrong_key.initResponder(other.rs, kPrologue, 9)); // a node that is not S_pub
    EXPECT_FALSE(wrong_key.readMessage1(msg, n, pt, m));
}

TEST(NoiseIK, LowOrderEphemeralIsRejected)
{
    Pair k;
    HandshakeIK I;
    ASSERT_TRUE(I.initInitiator(k.is, k.rs_pub, kPrologue, 9));
    uint8_t msg[256], pt[256];
    size_t n = 0, m = 0;
    ASSERT_TRUE(I.writeMessage1(nullptr, 0, msg, n));
    std::memset(msg, 0, kDhLen); // e = 0 (a low-order point): X25519 output is all zero
    HandshakeIK R;
    ASSERT_TRUE(R.initResponder(k.rs, kPrologue, 9));
    EXPECT_FALSE(R.readMessage1(msg, n, pt, m));
}

TEST(NoiseIK, RandomHandshakeAgreesOnKeysAndHash)
{
    Pair k;
    HandshakeIK I, R;
    ASSERT_TRUE(I.initInitiator(k.is, k.rs_pub, kPrologue, 9));
    ASSERT_TRUE(R.initResponder(k.rs, kPrologue, 9));
    uint8_t m1[256], m2[256], pt[256];
    size_t n1 = 0, n2 = 0, m = 0;
    ASSERT_TRUE(I.writeMessage1(nullptr, 0, m1, n1));
    ASSERT_TRUE(R.readMessage1(m1, n1, pt, m));
    ASSERT_TRUE(R.writeMessage2(reinterpret_cast<const uint8_t *>("hi"), 2, m2, n2));
    ASSERT_EQ(n2, HandshakeIK::kMsg2Overhead + 2);
    ASSERT_TRUE(I.readMessage2(m2, n2, pt, m));
    CipherState a, b, c, d;
    I.split(a, b);
    R.split(c, d);
    EXPECT_EQ(0, std::memcmp(a.key(), c.key(), kKeyLen));
    EXPECT_EQ(0, std::memcmp(b.key(), d.key(), kKeyLen));
    EXPECT_NE(0, std::memcmp(a.key(), b.key(), kKeyLen));
    EXPECT_EQ(0, std::memcmp(I.handshakeHash(), R.handshakeHash(), kHashLen));
}
