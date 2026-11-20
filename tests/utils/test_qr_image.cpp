// QrImage: QR grid (qrcodegen), PNG writer and terminal drawing used by `vpnctl issue` / `vpnctl qr`.
// The PNG is decoded here independently (chunk CRCs, zlib stored blocks, Adler-32, 1-bit rows) and
// every module's pixel is compared with the grid, so a viewer shows exactly the encoded code.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "utils/QrImage.h"

namespace
{

uint32_t be32(const uint8_t *p) { return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3]; }

uint32_t refCrc32(const uint8_t *p, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++)
    {
        c ^= p[i];
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
    }
    return ~c;
}

struct Image
{
    uint32_t w = 0, h = 0;
    std::vector<uint8_t> raw; // filtered rows
    bool white(uint32_t x, uint32_t y) const
    {
        const size_t row = (w + 7) / 8 + 1;
        return raw[y * row + 1 + x / 8] & (0x80 >> (x % 8));
    }
};

// Minimal PNG reader for what toPng writes; fails the test on any structural error.
Image decode(const std::vector<uint8_t> &png)
{
    Image img;
    static const uint8_t sig[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    EXPECT_EQ(0, std::memcmp(png.data(), sig, 8));
    std::vector<uint8_t> idat;
    size_t off = 8;
    bool end = false;
    while (off + 12 <= png.size() && !end)
    {
        const uint32_t len = be32(&png[off]);
        const std::string type(reinterpret_cast<const char *>(&png[off + 4]), 4);
        EXPECT_EQ(refCrc32(&png[off + 4], 4 + len), be32(&png[off + 8 + len])) << type << " CRC";
        const uint8_t *d = &png[off + 8];
        if (type == "IHDR")
        {
            img.w = be32(d);
            img.h = be32(d + 4);
            EXPECT_EQ(d[8], 1);  // bit depth
            EXPECT_EQ(d[9], 0);  // grayscale
            EXPECT_EQ(d[12], 0); // no interlace
        }
        else if (type == "IDAT")
            idat.insert(idat.end(), d, d + len);
        else if (type == "IEND")
            end = true;
        off += 12 + len;
    }
    EXPECT_TRUE(end);
    EXPECT_EQ(off, png.size()) << "bytes after IEND";
    // zlib: header, stored blocks, Adler-32
    EXPECT_EQ((idat[0] * 256 + idat[1]) % 31, 0);
    size_t p = 2;
    bool final = false;
    while (!final)
    {
        final = idat[p] & 1;
        EXPECT_EQ(idat[p] & 6, 0) << "stored block";
        const uint16_t len = uint16_t(idat[p + 1] | idat[p + 2] << 8), nlen = uint16_t(idat[p + 3] | idat[p + 4] << 8);
        EXPECT_EQ(uint16_t(~len), nlen);
        img.raw.insert(img.raw.end(), idat.begin() + p + 5, idat.begin() + p + 5 + len);
        p += 5 + len;
    }
    uint32_t a = 1, b = 0;
    for (uint8_t c : img.raw)
        a = (a + c) % 65521, b = (b + a) % 65521;
    EXPECT_EQ(be32(&idat[p]), (b << 16) | a);
    EXPECT_EQ(img.raw.size(), size_t(img.h) * ((img.w + 7) / 8 + 1));
    return img;
}

// A link of the size vpnctl issues for one node (~318 characters).
const std::string kLink = "cppvpn://import?b=" + std::string(300, 'A') + "Zz09_-";

} // namespace

TEST(QrImage, GridHasFinderPatternsAndFitsABundleLink)
{
    const qr::Grid g = qr::encode(kLink);
    const size_t n = g.size();
    ASSERT_GE(n, 21u);
    EXPECT_EQ((n - 17) % 4, 0u) << "size = 4 * version + 17";
    EXPECT_LE(n, 4u * 15 + 17) << "a one-node bundle stays a scannable size";
    for (const auto &row : g)
        ASSERT_EQ(row.size(), n);
    // Top-left finder: dark 7x7 ring, light ring, dark 3x3 centre (same at the other two corners).
    for (size_t ox : {size_t(0), n - 7})
        for (size_t oy : {size_t(0), n - 7})
        {
            if (ox && oy)
                continue; // no finder at bottom-right
            for (size_t y = 0; y < 7; y++)
                for (size_t x = 0; x < 7; x++)
                {
                    const size_t ring = std::max(x > 3 ? x - 3 : 3 - x, y > 3 ? y - 3 : 3 - y);
                    EXPECT_EQ(g[oy + y][ox + x], ring != 2) << "finder at " << ox << "," << oy;
                }
        }
}

TEST(QrImage, PngIsValidAndEveryPixelMatchesTheGrid)
{
    const qr::Grid g = qr::encode(kLink);
    const int scale = 8, border = 4, n = int(g.size());
    const Image img = decode(qr::toPng(g, scale, border));
    ASSERT_EQ(img.w, uint32_t((n + 2 * border) * scale));
    ASSERT_EQ(img.h, img.w);
    for (int my = -border; my < n + border; my++)
        for (int mx = -border; mx < n + border; mx++)
        {
            const bool dark = my >= 0 && mx >= 0 && my < n && mx < n && g[size_t(my)][size_t(mx)];
            const uint32_t px = uint32_t((mx + border) * scale + scale / 2), py = uint32_t((my + border) * scale + scale / 2);
            ASSERT_EQ(img.white(px, py), !dark) << "module " << mx << "," << my;
        }
}

TEST(QrImage, LargeImageSpansSeveralDeflateBlocks)
{
    const Image img = decode(qr::toPng(qr::encode(kLink), 40, 4)); // > 65535 raw bytes
    EXPECT_GT(img.raw.size(), 65535u);
}

TEST(QrImage, TerminalDrawingHasTwoModuleRowsPerLine)
{
    const qr::Grid g = qr::encode("hello");
    const std::string t = qr::toTerminal(g, 2);
    const size_t total = g.size() + 4, lines = (total + 1) / 2;
    size_t count = 0;
    for (size_t p = 0; (p = t.find('\n', p)) != std::string::npos; p++)
        count++;
    EXPECT_EQ(count, lines);
    EXPECT_EQ(t.rfind("\033[30;47m", 0), 0u) << "forced black-on-white, readable on dark terminals";
}

TEST(QrImage, TooLongTextIsRejected)
{
    EXPECT_THROW(qr::encode(std::string(5000, 'x')), std::length_error);
    EXPECT_THROW(qr::toPng({}, 8, 4), std::invalid_argument);
}
