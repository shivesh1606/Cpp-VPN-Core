// QrImage.h - QR code of a text (vpnctl access bundles) as a module grid, a PNG and a terminal drawing.
//
// The QR encoding is third_party/qrcodegen (Project Nayuki, MIT). The PNG writer is self-contained:
// 1-bit grayscale, zlib stream of stored (uncompressed) deflate blocks, so no zlib dependency.
//   PNG = signature | IHDR(w, h, depth 1, gray) | IDAT(zlib) | IEND, each chunk with its CRC-32
//   row = filter byte 0 | ceil(w/8) bytes, MSB = leftmost pixel, bit 1 = white
#ifndef UTILS_QRIMAGE_H
#define UTILS_QRIMAGE_H

#include <cstdint>
#include <string>
#include <vector>

namespace qr
{

// Square grid, true = dark module. Error correction level M (15 % of the symbol can be damaged).
// Throws std::length_error if the text does not fit a QR code.
using Grid = std::vector<std::vector<bool>>;
Grid encode(const std::string &text);

// PNG bytes: `scale` pixels per module, `border` light modules around the code (spec: >= 4).
std::vector<uint8_t> toPng(const Grid &g, int scale = 8, int border = 4);

// Terminal drawing: two module rows per text line with Unicode half blocks, black on a forced
// white background (ANSI colours), so it scans on dark and light terminals alike.
std::string toTerminal(const Grid &g, int border = 2);

} // namespace qr

#endif // UTILS_QRIMAGE_H
