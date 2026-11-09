#include "auth/IssuerKey.h"

#include <fcntl.h>
#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <vector>

#include "config/Ini.h"
#include "crypto/backends/SodiumAead.h"

namespace auth
{

namespace
{
constexpr char kMagic[8] = {'C', 'P', 'P', 'V', 'P', 'N', 'I', 'K'};
constexpr size_t kPlainLen = 1 + 64;
constexpr size_t kBoxLen = kPlainLen + crypto_secretbox_MACBYTES;
constexpr size_t kFileLen = 8 + 4 + 8 + 8 + crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES + kBoxLen;

void putU64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = uint8_t(v >> (8 * i));
}
uint64_t getU64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = v << 8 | p[i];
    return v;
}
bool deriveKey(const std::string &pass, const uint8_t *salt, uint64_t ops, uint64_t mem, uint8_t key[32])
{
    return crypto_pwhash(key, 32, pass.data(), pass.size(), salt, ops, size_t(mem),
                         crypto_pwhash_ALG_ARGON2ID13) == 0;
}
} // namespace

IssuerKey::~IssuerKey()
{
    sodium_memzero(sk, sizeof(sk));
}

bool generateIssuerKey(uint8_t key_id, IssuerKey &out)
{
    if (!crypto::sodiumReady())
        return false;
    out.key_id = key_id;
    return crypto_sign_keypair(out.pk, out.sk) == 0;
}

bool saveIssuerKey(const std::string &path, const IssuerKey &key, const std::string &passphrase,
                   KdfStrength strength, std::string &error)
{
    if (!crypto::sodiumReady())
    {
        error = "libsodium init failed";
        return false;
    }
    uint64_t ops = crypto_pwhash_OPSLIMIT_MODERATE, mem = crypto_pwhash_MEMLIMIT_MODERATE;
    if (strength == KdfStrength::kInteractive)
        ops = crypto_pwhash_OPSLIMIT_INTERACTIVE, mem = crypto_pwhash_MEMLIMIT_INTERACTIVE;
    else if (strength == KdfStrength::kSensitive)
        ops = crypto_pwhash_OPSLIMIT_SENSITIVE, mem = crypto_pwhash_MEMLIMIT_SENSITIVE;

    uint8_t file[kFileLen] = {0};
    std::memcpy(file, kMagic, 8);
    file[8] = 1;
    file[9] = key.key_id;
    file[10] = 2; // Argon2id v1.3
    putU64(file + 12, ops);
    putU64(file + 20, mem);
    uint8_t *salt = file + 28;
    uint8_t *nonce = salt + crypto_pwhash_SALTBYTES;
    uint8_t *box = nonce + crypto_secretbox_NONCEBYTES;
    randombytes_buf(salt, crypto_pwhash_SALTBYTES);
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

    uint8_t k[32], plain[kPlainLen];
    if (!deriveKey(passphrase, salt, ops, mem, k))
    {
        error = "key derivation failed (out of memory?)";
        return false;
    }
    plain[0] = key.key_id;
    std::memcpy(plain + 1, key.sk, 64);
    crypto_secretbox_easy(box, plain, kPlainLen, nonce, k);
    sodium_memzero(k, sizeof(k));
    sodium_memzero(plain, sizeof(plain));

    const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
    {
        error = "cannot create " + path + ": " + std::strerror(errno) +
                (errno == EEXIST ? " (an issuer key exists; never overwrite it: every ticket depends on it)" : "");
        return false;
    }
    const bool ok = fchmod(fd, 0600) == 0 && write(fd, file, kFileLen) == ssize_t(kFileLen) && fsync(fd) == 0;
    close(fd);
    if (!ok)
    {
        error = "cannot write " + path + ": " + std::strerror(errno);
        unlink(path.c_str());
    }
    return ok;
}

bool loadIssuerKey(const std::string &path, const std::string &passphrase, IssuerKey &out, std::string &error)
{
    std::string text;
    if (!config::readTextFile(path, text, error))
        return false;
    const uint8_t *f = reinterpret_cast<const uint8_t *>(text.data());
    if (text.size() != kFileLen || std::memcmp(f, kMagic, 8) != 0 || f[8] != 1 || f[10] != 2)
    {
        error = path + " is not an issuer key file";
        return false;
    }
    const uint64_t ops = getU64(f + 12), mem = getU64(f + 20);
    if (ops < crypto_pwhash_OPSLIMIT_MIN || ops > crypto_pwhash_OPSLIMIT_SENSITIVE * 4 ||
        mem < crypto_pwhash_MEMLIMIT_MIN || mem > crypto_pwhash_MEMLIMIT_SENSITIVE * 2)
    {
        error = path + ": implausible key-derivation parameters";
        return false;
    }
    const uint8_t *salt = f + 28, *nonce = salt + crypto_pwhash_SALTBYTES, *box = nonce + crypto_secretbox_NONCEBYTES;
    uint8_t k[32], plain[kPlainLen];
    if (!crypto::sodiumReady() || !deriveKey(passphrase, salt, ops, mem, k))
    {
        error = "key derivation failed (out of memory?)";
        return false;
    }
    const bool opened = crypto_secretbox_open_easy(plain, box, kBoxLen, nonce, k) == 0;
    sodium_memzero(k, sizeof(k));
    if (!opened || plain[0] != f[9])
    {
        sodium_memzero(plain, sizeof(plain));
        error = "wrong passphrase or damaged file: " + path;
        return false;
    }
    out.key_id = plain[0];
    std::memcpy(out.sk, plain + 1, 64);
    sodium_memzero(plain, sizeof(plain));
    crypto_sign_ed25519_sk_to_pk(out.pk, out.sk);
    return true;
}

} // namespace auth
