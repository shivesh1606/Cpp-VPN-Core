// Base64Url.h - base64url without padding (RFC 4648 section 5), used for keys in files, configs
// and logs. Portable (server and clients).
#ifndef CRYPTO_BASE64URL_H
#define CRYPTO_BASE64URL_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace crypto
{

std::string toBase64Url(const uint8_t *data, size_t len);
// Decodes base64url without padding; true only if it decodes to exactly `len` bytes.
bool fromBase64Url(const std::string &text, uint8_t *out, size_t len);

} // namespace crypto

#endif // CRYPTO_BASE64URL_H
