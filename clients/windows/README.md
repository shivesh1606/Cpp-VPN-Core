# Windows test client

A command-line client for testing the server from a Windows machine, without the Android app. It speaks both protocols:

- **v2** (`--protocol v2`, M4): Noise IK handshake + AEAD transport ([design 02](../../docs/design/02-handshake.md)). It uses the same C++ engine as the server's tests ([protocol/v2/Client.h](../../protocol/v2/Client.h)). Rekeys every 120 s, keepalives both ways.
- **v1** (default): `HELLO / WELCOME / CLIENT_ACK / DATA / BYE / KEEPALIVE`, toy DH, 1-byte XOR. Insecure; kept for comparison until M7.

| Mode | What it does | Needs |
|---|---|---|
| `--probe` | Handshake, keepalives, BYE. Prints the HELLO→WELCOME time. No adapter. | Nothing (no admin) |
| tunnel (default) | Creates a Wintun adapter, sets IP/MTU/DNS/routes, forwards packets, auto-reconnects | Elevated terminal, `wintun.dll` next to the exe |

## Build

The MSYS2 MinGW-w64 toolchain is enough (`g++`, `cmake`, `ninja`), plus libsodium (`pacman -S mingw-w64-x86_64-libsodium`):

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

Protocol v2:

```powershell
# 1. Client key (once). Put the printed public key into the node's /etc/cppvpn/allowed_clients
build\windows-client\vpn_client.exe --gen-key client.key
# 2. Node public key: on the node, vpn_server --pubkey /etc/cppvpn/node.key
build\windows-client\vpn_client.exe --protocol v2 --server-pub <S_pub> --key client.key --probe 35.x.x.x 5555
build\windows-client\vpn_client.exe --protocol v2 --server-pub <S_pub> --key client.key 35.x.x.x 5555   # tunnel (admin)
```

With a ticket bundle from `vpnctl issue` (design 03), the bundle replaces all of the above: it sets the server, port, node key, device key and ticket. `--node ID` picks a node when the bundle lists several. Bundle hosts may be DNS names.

```powershell
build\windows-client\vpn_client.exe --bundle alice.txt --probe      # or: --bundle "cppvpn://import?b=..."
build\windows-client\vpn_client.exe --bundle alice.txt              # tunnel (admin)
```

The bundle contains the device private key: keep the file private.

A v2 probe prints `v2 established: hsid=… ip=… cipher=…` and ends with `PROBE OK (v2)`. The server logs the same `hsid`. `--rekey-after 8 --duration 25` makes rekeys visible in a probe.

Options: `--probe`, `--duration SEC`, `--route-all`, `--log-level error|warn|info|debug`, `--config FILE`, `--protocol v1|v2`, `--server-pub B64`, `--key FILE`, `--gen-key FILE`, `--pubkey FILE`, `--rekey-after SEC`, `--bundle FILE|URI`, `--node ID`, `-h`.

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

### v2 against the local Docker server

```bash
export MSYS_NO_PATHCONV=1
PUB=$(build/windows-client/vpn_client.exe --gen-key build/windows-client/client.key)
docker run -d --name cppvpn-win --cap-add NET_ADMIN --device /dev/net/tun:/dev/net/tun -p 5555:5555/udp \
  vpn-builder-stage sleep infinity
docker exec cppvpn-win sh -c "mkdir -p /etc/cppvpn && /src/build/vpn_server --gen-key /etc/cppvpn/node.key \
  && cp /src/deploy/node.conf.example /etc/cppvpn/node.conf && echo '$PUB windows' > /etc/cppvpn/allowed_clients \
  && (/src/build/vpn_server >/tmp/server.log 2>&1 &)"
build/windows-client/vpn_client.exe --protocol v2 --probe --duration 25 --rekey-after 8 \
  --server-pub $(docker exec cppvpn-win /src/build/vpn_server --pubkey /etc/cppvpn/node.key) \
  --key build/windows-client/client.key 127.0.0.1 5555
docker exec cppvpn-win cat /tmp/server.log; docker rm -f cppvpn-win
```

## Known v1 limitations (by design of protocol v1, fixed in v2)

- **No idle liveness:** the v1 server never sends anything to an idle client, so `timeout` defaults to 0 (disabled). In v2, KEEPALIVE goes both ways (design 02 §3.1).
- **Single IPv4 server address:** no DNS names.
- **No security:** the XOR key is 1 byte and nothing is authenticated (design 01 §1). Use only for testing.

## Files

| File | Purpose |
|---|---|
| `main.cpp` | Client: config, Wintun, routes/DNS, v1 protocol |
| `ProtocolV2.inc` | v2: key files, handshake, probe and tunnel loops on the shared `v2::Client` engine |
| `wintun.h`, `wintun.dll` | [Wintun](https://www.wintun.net/) 0.14.1 by WireGuard LLC (Authenticode-signed, amd64, redistributed unmodified) |
| `vpn_client.conf.example` | All config keys with defaults |
| `build.ps1` | One-command build |
