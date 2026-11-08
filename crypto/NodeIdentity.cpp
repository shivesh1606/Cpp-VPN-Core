#include "crypto/NodeIdentity.h"

#include <fcntl.h>
#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

#include "config/Ini.h"
#include "crypto/backends/SodiumAead.h"

namespace crypto
{

NodeIdentity::~NodeIdentity()
{
    sodium_memzero(sk_, sizeof(sk_));
}

bool NodeIdentity::setPrivateKey(const uint8_t sk[kX25519Bytes])
{
    if (!sodiumReady())
        return false;
    std::memcpy(sk_, sk, kX25519Bytes);
    loaded_ = crypto_scalarmult_base(pk_, sk_) == 0;
    return loaded_;
}

std::string NodeIdentity::publicKeyBase64Url() const
{
    return toBase64Url(pk_, kX25519Bytes);
}

namespace
{

std::string errnoText(const std::string &what, const std::string &path)
{
    return what + " " + path + ": " + std::strerror(errno);
}

bool writeAll(int fd, const std::string &s)
{
    size_t off = 0;
    while (off < s.size())
    {
        const ssize_t n = write(fd, s.data() + off, s.size() - off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

} // namespace

bool generateNodeKey(const std::string &path, bool overwrite, NodeIdentity &out, std::string &error)
{
    if (!sodiumReady())
    {
        error = "libsodium initialisation failed";
        return false;
    }
    struct stat st{};
    if (!overwrite && lstat(path.c_str(), &st) == 0)
    {
        error = path + " already exists (use --force to replace it; this changes the node's "
                       "public key and invalidates every issued bundle)";
        return false;
    }

    uint8_t sk[kX25519Bytes];
    randombytes_buf(sk, sizeof(sk));
    std::string line = toBase64Url(sk, sizeof(sk)) + "\n";

    const std::string tmp = path + ".tmp";
    unlink(tmp.c_str());
    const int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    bool ok = fd >= 0;
    if (!ok)
        error = errnoText("cannot create", tmp);
    else
    {
        ok = fchmod(fd, 0600) == 0 && writeAll(fd, line) && fsync(fd) == 0;
        if (!ok)
            error = errnoText("cannot write", tmp);
        if (close(fd) != 0 && ok)
        {
            ok = false;
            error = errnoText("cannot close", tmp);
        }
    }
    if (ok && rename(tmp.c_str(), path.c_str()) != 0)
    {
        ok = false;
        error = errnoText("cannot rename to", path);
    }
    if (!ok)
        unlink(tmp.c_str());
    else if (!out.setPrivateKey(sk))
    {
        ok = false;
        error = "cannot derive public key";
    }
    sodium_memzero(sk, sizeof(sk));
    sodium_memzero(&line[0], line.size());
    return ok;
}

bool loadNodeKey(const std::string &path, NodeIdentity &out, std::string &error)
{
    struct stat st{};
    if (stat(path.c_str(), &st) != 0)
    {
        error = errnoText("cannot read node key", path) +
                " (create it with: vpn_server --gen-key " + path + ")";
        return false;
    }
    if (!S_ISREG(st.st_mode))
    {
        error = path + " is not a regular file";
        return false;
    }
    if (st.st_mode & 077)
    {
        char mode[8];
        std::snprintf(mode, sizeof(mode), "%04o", static_cast<unsigned>(st.st_mode & 07777));
        error = path + " has mode " + mode + "; a private key must be readable by its owner only "
                "(chmod 600 " + path + ")";
        return false;
    }

    std::string text;
    if (!config::readTextFile(path, text, error))
        return false;
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' '))
        text.pop_back();

    uint8_t sk[kX25519Bytes];
    const bool decoded = fromBase64Url(text, sk, sizeof(sk));
    sodium_memzero(&text[0], text.size());
    if (!decoded)
    {
        error = path + " is not a node key (expected one line: 43 base64url characters)";
        return false;
    }
    const bool ok = out.setPrivateKey(sk);
    sodium_memzero(sk, sizeof(sk));
    if (!ok)
        error = "cannot derive public key from " + path;
    return ok;
}

} // namespace crypto
