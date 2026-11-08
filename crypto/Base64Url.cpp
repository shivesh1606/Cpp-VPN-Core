#include "crypto/Base64Url.h"

#include <sodium.h>

#include <cstring>

#include "crypto/backends/SodiumAead.h"

namespace crypto
{

std::string toBase64Url(const uint8_t *data, size_t len)
{
    const int variant = sodium_base64_VARIANT_URLSAFE_NO_PADDING;
    std::string out(sodium_base64_encoded_len(len, variant), '\0');
    sodium_bin2base64(&out[0], out.size(), data, len, variant);
    out.resize(std::strlen(out.c_str())); // drop the terminating NUL
    return out;
}

bool fromBase64Url(const std::string &text, uint8_t *out, size_t len)
{
    size_t got = 0;
    const char *end = nullptr;
    if (!sodiumReady() ||
        sodium_base642bin(out, len, text.c_str(), text.size(), nullptr, &got, &end,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        return false;
    return got == len && end == text.c_str() + text.size();
}

} // namespace crypto
