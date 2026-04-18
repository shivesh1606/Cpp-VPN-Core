# VPN Client

This folder contains the Linux desktop VPN client for the Cpp-VPN-Core project.

## Build

From the repository root:

```bash
cmake -B build
cmake --build build --target vpn_client
```

The client is built as a separate target using the root repository sources.

## Run

Requires root privileges to create and configure the TUN interface:

```bash
sudo ./build/vpn_client <server-ip> <server-port> [tun-name]
```

Example:

```bash
sudo ./build/vpn_client 10.0.0.1 5555 tun0
```

## Notes

- The client uses the existing server-side handshake protocol defined in `protocol/Handshake.h`.
- Packet encryption/decryption uses the existing XOR cipher implementation.
- The TUN device must be configured on Linux.

## Future Improvements

See `FUTURE_IMPROVEMENTS.md` for planned enhancements to the client, security, protocol, and cross-platform support.
