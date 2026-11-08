# Windows test client

A command-line client for testing the server from a Windows machine, without the Android app. It speaks **protocol v1** (as on `master`): `HELLO / WELCOME / CLIENT_ACK / DATA / BYE / KEEPALIVE`, toy DH, 1-byte XOR. It will be upgraded to protocol v2 first, ahead of Android (see the [implementation plan](../../docs/plan/implementation-plan.md), M4).

| Mode | What it does | Needs |
|---|---|---|
| `--probe` | Handshake, keepalives, BYE. Prints the HELLO→WELCOME time. No adapter. | Nothing (no admin) |
| tunnel (default) | Creates a Wintun adapter, sets IP/MTU/DNS/routes, forwards packets, auto-reconnects | Elevated terminal, `wintun.dll` next to the exe |

## Build

The MSYS2 MinGW-w64 toolchain is enough (`g++`, `cmake`, `ninja`):

```powershell
.\clients\windows\build.ps1          # → build\windows-client\vpn_client.exe (+ wintun.dll copied next to it)
```

or manually:

```bash
cmake -S clients/windows -B build/windows-client -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/windows-client
```

The exe is statically linked, so it runs from any terminal without MSYS2 DLLs.

## Run

```powershell
# Quick health check of a server (no admin):
build\windows-client\vpn_client.exe --probe 35.x.x.x 5555

# Full tunnel, VPN subnet only (Administrator terminal):
build\windows-client\vpn_client.exe 35.x.x.x 5555

# Full tunnel, all IPv4 traffic through the VPN:
build\windows-client\vpn_client.exe --route-all 35.x.x.x 5555

# Settings from a file (CLI arguments override the file):
build\windows-client\vpn_client.exe --config clients\windows\vpn_client.conf.example
```

Options: `--probe`, `--duration SEC`, `--route-all`, `--log-level error|warn|info|debug`, `--config FILE`, `-h`.

A successful probe ends with `PROBE OK`; exit codes are 0 = ok, 2 = no WELCOME. The server log should then show `Handshake: Client … Session ID N`, followed by `[BYE] Removing client session N`.

## Local server for testing (Docker Desktop)

This runs the real `vpn_server` locally, with TUN access, published on `localhost:5555/udp`:

```bash
docker build --target builder -t vpn-builder-stage .
MSYS_NO_PATHCONV=1 docker run -d --name cppvpn-e2e --cap-add NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun -p 5555:5555/udp vpn-builder-stage /src/build/vpn_server
build/windows-client/vpn_client.exe --probe --duration 6 127.0.0.1 5555
MSYS_NO_PATHCONV=1 docker logs cppvpn-e2e        # server log
docker rm -f cppvpn-e2e                           # clean up
```

For a tunnel-mode test against the container, give the server's `tun0` an address first:

```bash
MSYS_NO_PATHCONV=1 docker exec cppvpn-e2e sh -c "ip addr add 10.8.0.1/24 dev tun0 && ip link set tun0 up"
# The builder image may lack iproute2; if so: docker exec cppvpn-e2e apt-get install -y iproute2
```

Then run the client in tunnel mode (elevated) and `ping 10.8.0.1`.

## Known v1 limitations (by design of protocol v1, fixed in v2)

- **No idle liveness:** the v1 server never sends anything to an idle client, so `timeout` defaults to 0 (disabled). In v2, KEEPALIVE goes both ways (design 02 §3.1).
- **Single IPv4 server address:** no DNS names.
- **No security:** the XOR key is 1 byte and nothing is authenticated (design 01 §1). Use only for testing.

## Files

| File | Purpose |
|---|---|
| `main.cpp` | Client (single file) |
| `wintun.h`, `wintun.dll` | [Wintun](https://www.wintun.net/) 0.14.1 by WireGuard LLC (Authenticode-signed, amd64, redistributed unmodified) |
| `vpn_client.conf.example` | All config keys with defaults |
| `build.ps1` | One-command build |
