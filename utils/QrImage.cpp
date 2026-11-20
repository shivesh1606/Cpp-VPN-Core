#include "utils/QrImage.h"

#include <algorithm>
#include <stdexcept>

#include "third_party/qrcodegen/qrcodegen.hpp"

namespace qr
{

namespace
{

uint32_t crc32(const uint8_t *p, size_t n, uint32_t crc = 0)
{
    static uint32_t table[256];
    static bool init = false;
    if (!init)
    {
        for (uint32_t i = 0; i < 256; i++)
        {
            uint32_t c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        init = true;
    }
    crc = ~crc;
    for (size_t i = 0; i < n; i++)
        crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

void putBe32(std::vector<uint8_t> &v, uint32_t x)
{
    for (int i = 3; i >= 0; i--)
        v.push_back(uint8_t(x >> (8 * i)));
}

void chunk(std::vector<uint8_t> &png, const char type[4], const std::vector<uint8_t> &data)
{
    putBe32(png, uint32_t(data.size()));
    std::vector<uint8_t> body(type, type + 4);
    body.insert(body.end(), data.begin(), data.end());
    png.insert(png.end(), body.begin(), body.end());
    putBe32(png, crc32(body.data(), body.size()));
}

// zlib stream (RFC 1950) holding stored deflate blocks (RFC 1951 section 3.2.4).
std::vector<uint8_t> zlibStored(const std::vector<uint8_t> &raw)
{
    std::vector<uint8_t> z{0x78, 0x01};
    size_t off = 0;
    do
    {
        const size_t len = std::min<size_t>(65535, raw.size() - off);
        const bool final = off + len == raw.size();
        z.push_back(final ? 1 : 0); // BFINAL, BTYPE = 00 (stored)
        z.push_back(uint8_t(len));
        z.push_back(uint8_t(len >> 8));
        z.push_back(uint8_t(~len));
        z.push_back(uint8_t(~len >> 8));
        z.insert(z.end(), raw.begin() + off, raw.begin() + off + len);
        off += len;
    } while (off < raw.size());
    uint32_t a = 1, b = 0; // Adler-32
    for (uint8_t c : raw)
    {
        a = (a + c) % 65521;
        b = (b + a) % 65521;
    }
    putBe32(z, (b << 16) | a);
    return z;
}

} // namespace

Grid encode(const std::string &text)
{
    using qrcodegen::QrCode;
    const QrCode q = QrCode::encodeText(text.c_str(), QrCode::Ecc::MEDIUM); // throws data_too_long
    Grid g(size_t(q.getSize()), std::vector<bool>(size_t(q.getSize())));
    for (int y = 0; y < q.getSize(); y++)
        for (int x = 0; x < q.getSize(); x++)
            g[size_t(y)][size_t(x)] = q.getModule(x, y);
    return g;
}

std::vector<uint8_t> toPng(const Grid &g, int scale, int border)
{
    if (g.empty() || scale < 1 || border < 0)
        throw std::invalid_argument("qr::toPng: empty grid or bad scale/border");
    const int n = int(g.size());
    const uint32_t w = uint32_t((n + 2 * border) * scale);
    const size_t row_bytes = (w + 7) / 8;
    std::vector<uint8_t> raw;
    raw.reserve(w * (row_bytes + 1));
    for (uint32_t py = 0; py < w; py++)
    {
        raw.push_back(0); // filter: none
        const int my = int(py) / scale - border;
        std::vector<uint8_t> row(row_bytes, 0);
        for (uint32_t px = 0; px < w; px++)
        {
            const int mx = int(px) / scale - border;
            const bool dark = my >= 0 && my < n && mx >= 0 && mx < n && g[size_t(my)][size_t(mx)];
            if (!dark)
                row[px / 8] |= uint8_t(0x80 >> (px % 8)); // 1 = white
        }
        raw.insert(raw.end(), row.begin(), row.end());
    }
    std::vector<uint8_t> png{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    std::vector<uint8_t> ihdr;
    putBe32(ihdr, w);
    putBe32(ihdr, w);
    ihdr.insert(ihdr.end(), {1, 0, 0, 0, 0}); // depth 1, grayscale, deflate, filter 0, no interlace
    chunk(png, "IHDR", ihdr);
    chunk(png, "IDAT", zlibStored(raw));
    chunk(png, "IEND", {});
    return png;
}

std::string toTerminal(const Grid &g, int border)
{
    const int n = int(g.size());
    auto dark = [&](int x, int y) {
        x -= border;
        y -= border;
        return x >= 0 && y >= 0 && x < n && y < n && g[size_t(y)][size_t(x)];
    };
    const int total = n + 2 * border;
    std::string s;
    for (int y = 0; y < total; y += 2)
    {
        s += "\033[30;47m"; // black on white
        for (int x = 0; x < total; x++)
        {
            const bool top = dark(x, y), bottom = y + 1 < total && dark(x, y + 1);
            s += top && bottom ? "█" : top ? "▀" : bottom ? "▄" : " ";
        }
        s += "\033[0m\n";
    }
    return s;
}

} // namespace qr
