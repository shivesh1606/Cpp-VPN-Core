# qrcodegen (vendored)

QR Code generator library, C++ version, by Project Nayuki. MIT License (header of each file).

- Source: https://github.com/nayuki/QR-Code-generator, tag `v1.8.0`, directory `cpp/`
- Files copied unmodified:
  - `qrcodegen.hpp` sha256 `b779c3b156cf7a57ce789d6fee4fc991ccc2913774d26c909d22bb8f26b2a793`
  - `qrcodegen.cpp` sha256 `1f3b3fcdac6954c32cf583ccd02ec9b5901f756a38c461acedc70be4a77d3757`
- Used by `vpnctl` only (QR code of an access bundle), through `utils/QrImage.h`; not linked into `vpn_server`.
