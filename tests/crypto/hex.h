// Test helper: hex string <-> bytes. Whitespace and ':' are ignored, so vectors can be pasted
// in the layout their source document uses.
#ifndef TESTS_CRYPTO_HEX_H
#define TESTS_CRYPTO_HEX_H

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

inline std::vector<uint8_t> hex(const std::string &s)
{
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    int hi = -1;
    for (char c : s)
    {
        if (c == ' ' || c == '\n' || c == ':')
            continue;
        const int v = nibble(c);
        if (v < 0)
            throw std::invalid_argument("bad hex character");
        if (hi < 0)
            hi = v;
        else
        {
            out.push_back(static_cast<uint8_t>(hi << 4 | v));
            hi = -1;
        }
    }
    if (hi >= 0)
        throw std::invalid_argument("odd number of hex digits");
    return out;
}

inline std::vector<uint8_t> bytesOf(const std::string &s) { return {s.begin(), s.end()}; }

#endif // TESTS_CRYPTO_HEX_H
