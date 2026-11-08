#include "crypto/backends/XorBackend.h"

#include <cstring>

namespace crypto
{

static inline void xorBytes(const uint8_t *in, size_t len, uint8_t *out, uint8_t key)
{
    for (size_t i = 0; i < len; i++)
        out[i] = in[i] ^ key;
}

void XorLock::seal(uint64_t, const uint8_t *, size_t, const uint8_t *in, size_t len, uint8_t *out)
{
    xorBytes(in, len, out, key_);
}

bool XorLock::open(uint64_t, const uint8_t *, size_t, const uint8_t *in, size_t len, uint8_t *out)
{
    xorBytes(in, len, out, key_); // no integrity: always "succeeds"
    return true;
}

std::unique_ptr<SessionLock> XorBackend::newLock(const uint8_t key[kKeyBytes]) const
{
    return std::make_unique<XorLock>(key[0]);
}

void expandV1XorKey(uint8_t xor_key, uint8_t out[kKeyBytes])
{
    std::memset(out, 0, kKeyBytes);
    out[0] = xor_key;
}

} // namespace crypto
