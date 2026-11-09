#!/bin/bash
# End-to-end checks in Docker (needs a TUN device and NET_ADMIN, so not part of ctest).
#   A) no config file  -> legacy behaviour: tun0 configured externally, pool 10.8.0.2 x 100
#   B) with node.conf  -> node key required; the server configures tun0 from tun_cidr itself
# Each scenario runs tests/e2e/v1_roundtrip.py (v1 handshake + ICMP through the tunnel + BYE).
#
# Usage: bash tests/e2e/run_docker_e2e.sh [image]     (default image: vpn-builder-stage)
# Build the image first: docker build --target builder -t vpn-builder-stage .
set -u
export MSYS_NO_PATHCONV=1 # Git Bash on Windows: keep /dev/net/tun etc. as-is
IMG="${1:-vpn-builder-stage}"
C=cppvpn-e2e
fail=0

start() { # $1 = shell command run inside the container before the server
    docker rm -f $C >/dev/null 2>&1
    docker run -d --name $C --cap-add NET_ADMIN --device /dev/net/tun:/dev/net/tun \
        "$IMG" sleep infinity >/dev/null || exit 1
    docker exec $C sh -c "apt-get update -qq >/dev/null && apt-get install -y -qq iproute2 python3 >/dev/null 2>&1"
    docker exec $C sh -c "$1"
}
check() { # $1 = scenario name
    sleep 2
    if docker exec $C python3 /src/tests/e2e/v1_roundtrip.py 127.0.0.1 5555 10.8.0.1; then
        echo "[$1] PASS"
    else
        echo "[$1] FAIL"; fail=1
        docker exec $C cat /tmp/server.log | tail -20
    fi
    docker exec $C sh -c "ip -4 addr show tun0 | grep inet; grep -E 'config: (source|client pool|tunnel)|Node public key|No node identity|TUN tun0 configured' /tmp/server.log"
}

echo "=== A: no config file (pre-M3 behaviour) ==="
start "(/src/build/vpn_server >/tmp/server.log 2>&1 &) ; sleep 1; ip addr add 10.8.0.1/24 dev tun0 && ip link set tun0 up"
check A

echo "=== B: node.conf + node key; server configures tun0 ==="
start "mkdir -p /etc/cppvpn && /src/build/vpn_server --gen-key /etc/cppvpn/node.key \
  && cp /src/deploy/node.conf.example /etc/cppvpn/node.conf \
  && /src/build/vpn_server --check-config >/dev/null \
  && (/src/build/vpn_server >/tmp/server.log 2>&1 &)"
check B

echo "=== C: node.conf without a key must refuse to start ==="
start "mkdir -p /etc/cppvpn && cp /src/deploy/node.conf.example /etc/cppvpn/node.conf"
if docker exec $C /src/build/vpn_server >/dev/null 2>&1; then
    echo "[C] FAIL: server started without a node key"; fail=1
else
    echo "[C] PASS: refused (exit $?)"
fi

docker rm -f $C >/dev/null 2>&1
exit $fail
