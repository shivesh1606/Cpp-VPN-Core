#!/bin/bash
# End-to-end checks in Docker (needs a TUN device and NET_ADMIN, so not part of ctest).
#   A) no config file  -> legacy behaviour: v1 only, tun0 configured externally, pool .2 x 100
#   B) node.conf + key -> server configures tun0; v1 still works (accept_v1); v2 handshake, ping,
#                         rekey and BYE work for an allowed client; lost ACK is covered by DATA
#   C) node.conf without a key -> refuses to start
#   D) v2 client that is not in allowed_clients -> no session (HS_DROP_AUTH)
#   E) accept_v1 = false -> v1 is refused, v2 still works
#   F) auth.mode = ticket with vpnctl (design 03): issued bundle connects (and rekeys); a ticket out
#      of scope / no ticket is refused; revoking a connected user drops the session within seconds
#      (BYE) and the user cannot reconnect
# v1 uses tests/e2e/v1_roundtrip.py; v2 uses build/vpn_client_v2 (ICMP echo through the tunnel).
#
# Usage: bash tests/e2e/run_docker_e2e.sh [image]     (default image: vpn-builder-stage)
# Build the image first: docker build --target builder -t vpn-builder-stage .
set -u
export MSYS_NO_PATHCONV=1 # Git Bash on Windows: keep /dev/net/tun etc. as-is
IMG="${1:-vpn-builder-stage}"
C=cppvpn-e2e
B=/src/build
fail=0

start() { # $1 = shell command run inside a fresh container
    docker rm -f $C >/dev/null 2>&1
    docker run -d --name $C --cap-add NET_ADMIN --device /dev/net/tun:/dev/net/tun \
        "$IMG" sleep infinity >/dev/null || exit 1
    docker exec $C sh -c "apt-get update -qq >/dev/null && apt-get install -y -qq iproute2 python3 >/dev/null 2>&1"
    docker exec $C sh -c "$1"
}
result() { # $1 = name, $2 = exit code of the check, $3 = 0 if success is expected, 1 if failure is
    if { [ "$3" = 0 ] && [ "$2" = 0 ]; } || { [ "$3" = 1 ] && [ "$2" != 0 ]; }; then
        echo "[$1] PASS"
    else
        echo "[$1] FAIL (exit $2)"; fail=1
        docker exec $C sh -c "tail -25 /tmp/server.log"
    fi
}
v1() { docker exec $C python3 /src/tests/e2e/v1_roundtrip.py 127.0.0.1 5555 10.8.0.1; }
v2() { # $1 = client key file in the container, rest = extra client options
    local key=$1; shift
    docker exec $C sh -c "$B/vpn_client_v2 --key $key --server-pub \$($B/vpn_server --pubkey /etc/cppvpn/node.key) --ping 10.8.0.1 $*"
}
# node.conf from the example, the node key, and an allowed_clients file with the client key.
SETUP_NODE="mkdir -p /etc/cppvpn && $B/vpn_server --gen-key /etc/cppvpn/node.key >/dev/null \
  && cp /src/deploy/node.conf.example /etc/cppvpn/node.conf \
  && $B/vpn_client_v2 --gen-key /root/client.key > /tmp/client.pub \
  && $B/vpn_client_v2 --gen-key /root/stranger.key >/dev/null \
  && echo \"\$(cat /tmp/client.pub) e2e-client\" > /etc/cppvpn/allowed_clients"
RUN_SERVER="($B/vpn_server \$EXTRA >/tmp/server.log 2>&1 &) ; sleep 2"

echo "=== A: no config file (pre-M3 behaviour, v1 only) ==="
start "($B/vpn_server >/tmp/server.log 2>&1 &) ; sleep 1; ip addr add 10.8.0.1/24 dev tun0 && ip link set tun0 up"
sleep 1; v1; result A-v1 $? 0
docker exec $C sh -c "grep -E 'No node identity|client pool' /tmp/server.log"

echo "=== B: node.conf + node key: v1 and v2 side by side ==="
start "$SETUP_NODE && EXTRA= && $RUN_SERVER"
v1; result B-v1 $? 0
v2 /root/client.key --count 3 --rekey; result B-v2-rekey $? 0
v2 /root/client.key --count 2 --drop-ack; result B-v2-lost-ack $? 0
v2 /root/client.key --count 2 --offer aes256gcm; result B-v2-aes $? 0
sleep 1
docker exec $C sh -c "ip -4 addr show tun0 | grep inet; grep -E 'Protocol v2 enabled|v2 (handshake|rekey|session ACTIVE)|v2 BYE|^.*v2: active' /tmp/server.log | tail -12"

echo "=== C: node.conf without a key must refuse to start ==="
start "mkdir -p /etc/cppvpn && cp /src/deploy/node.conf.example /etc/cppvpn/node.conf && touch /etc/cppvpn/allowed_clients"
docker exec $C $B/vpn_server >/dev/null 2>&1; result C-no-key $? 1

echo "=== D: v2 client not in allowed_clients gets no session ==="
start "$SETUP_NODE && EXTRA= && $RUN_SERVER"
v2 /root/stranger.key --count 1 >/dev/null 2>&1; result D-not-allowed $? 1   # 4 attempts x 5 s
docker exec $C sh -c "grep -m1 'not in allowed_clients' /tmp/server.log"

echo "=== E: accept_v1 = false ==="
start "$SETUP_NODE && EXTRA='--set node.accept_v1=false' && $RUN_SERVER"
v1 >/dev/null 2>&1; result E-v1-refused $? 1
v2 /root/client.key --count 2 >/dev/null; result E-v2-works $? 0

echo "=== F: tickets issued by vpnctl ==="
start "$SETUP_NODE && export VPNCTL_DIR=/root/issuer VPNCTL_PASSPHRASE=e2e-passphrase-0123   && $B/vpnctl init --kdf interactive >/dev/null && cp /root/issuer/tags.conf /etc/cppvpn/tags.conf   && $B/vpnctl node add --id local --host 127.0.0.1 --port 5555        --pub \$($B/vpn_server --pubkey /etc/cppvpn/node.key) --tags friends >/dev/null   && $B/vpnctl issue --user alice --tags friends --days 1 > /root/alice.txt 2>/dev/null   && $B/vpnctl issue --user bob --tags premium --nodes local > /root/bob.txt 2>/dev/null   && EXTRA=\"--set auth.mode=ticket --set node.tags=friends --set auth.issuer_pk.1=\$(cut -d' ' -f3 /root/issuer/issuer.pub)\"   && $RUN_SERVER"
docker exec $C sh -c "$B/vpn_client_v2 --bundle /root/alice.txt --ping 10.8.0.1 --count 2 --rekey"; result F-bundle-rekey $? 0
docker exec $C sh -c "$B/vpn_client_v2 --bundle /root/bob.txt --ping 10.8.0.1 --count 1" >/dev/null 2>&1; result F-out-of-scope $? 1
v2 /root/client.key --count 1 >/dev/null 2>&1; result F-no-ticket $? 1
# Revocation while connected: alice holds a session; revoke her and install the new list.
docker exec -d $C sh -c "$B/vpn_client_v2 --bundle /root/alice.txt --ping 10.8.0.1 --count 1 --hold 40 >/tmp/hold.log 2>&1; echo \$? > /tmp/hold.rc"
sleep 4
docker exec $C sh -c "VPNCTL_DIR=/root/issuer VPNCTL_PASSPHRASE=e2e-passphrase-0123 $B/vpnctl revoke --user alice >/dev/null   && date +%s.%N > /tmp/revoked_at && cp /root/issuer/revocations.bin /etc/cppvpn/revocations.bin"
for i in $(seq 1 20); do docker exec $C test -f /tmp/hold.rc && break; sleep 1; done
rc=$(docker exec $C cat /tmp/hold.rc 2>/dev/null || echo none)
[ "$rc" = 3 ]; result F-revoked-dropped $? 0
docker exec $C sh -c "grep -E 'session ended|ENDED' /tmp/hold.log; grep -E 'Revocations:' /tmp/server.log | tail -2"
docker exec $C sh -c "$B/vpn_client_v2 --bundle /root/alice.txt --ping 10.8.0.1 --count 1" >/dev/null 2>&1; result F-revoked-reconnect $? 1
sleep 1
docker exec $C sh -c "grep -E 'ticket=.* reason=' /tmp/server.log | sed 's/.*reason=/reason=/' | sort | uniq -c; grep 'v2: active' /tmp/server.log | tail -1 | grep -o 'ticket drop.*'"

docker rm -f $C >/dev/null 2>&1
[ $fail = 0 ] && echo "ALL E2E SCENARIOS PASSED" || echo "E2E FAILURES"
exit $fail
