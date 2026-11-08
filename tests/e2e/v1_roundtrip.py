#!/usr/bin/env python3
"""End-to-end protocol v1 check against a running vpn_server (not part of ctest: needs TUN + root).

Performs the real v1 handshake (HELLO/WELCOME/CLIENT_ACK, DH P=127, 1-byte XOR), then sends an
XOR-encrypted ICMP echo request to the server's tun0 address through the tunnel and expects the
echo reply back through the tunnel. This exercises both data paths of main.cpp:
  UDP -> handleUdpToTun -> SessionLock::open -> write(tun)
  read(tun) -> ipv4Destination -> SessionLock::seal -> sendmmsg
then sends BYE.

Setup (server container): ip addr add 10.8.0.1/24 dev tun0 && ip link set tun0 up
Usage: python3 v1_roundtrip.py [server_ip] [port] [tun_peer_ip]
Exit code 0 = pass.
"""
import random
import socket
import struct
import sys
import time

P, G = 127, 9
PKT_HELLO, PKT_WELCOME, PKT_CLIENT_ACK, PKT_DATA, PKT_BYE = 1, 2, 3, 4, 5


def xor_key(s: int) -> int:
    return (s ^ (s >> 8) ^ (s >> 16) ^ (s >> 24)) & 0xFF


def xor(data: bytes, k: int) -> bytes:
    return bytes(b ^ k for b in data)


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def icmp_echo(src: str, dst: str, ident: int, seq: int, payload: bytes) -> bytes:
    icmp = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    total = 20 + len(icmp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0, 64, 1, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ip + icmp


def main() -> int:
    server = (sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1",
              int(sys.argv[2]) if len(sys.argv) > 2 else 5555)
    tun_peer = sys.argv[3] if len(sys.argv) > 3 else "10.8.0.1"

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)

    # ---- handshake ----
    a = random.randint(1000, 5000)
    magic = random.getrandbits(32)
    s.sendto(struct.pack("!BIII", PKT_HELLO, 0, magic, pow(G, a, P)), server)
    data, _ = s.recvfrom(2048)
    typ, sid, ip_n, ys = struct.unpack("!BIII", data[:13])
    if typ != PKT_WELCOME:
        print(f"FAIL: expected WELCOME, got type {typ}")
        return 1
    key = xor_key(pow(ys, a, P))
    my_ip = socket.inet_ntoa(struct.pack("!I", ip_n))
    s.sendto(struct.pack("!BI", PKT_CLIENT_ACK, sid), server)
    print(f"handshake ok: session={sid} ip={my_ip} xor_key={key}")
    time.sleep(0.2)  # let the server process ACK before DATA

    # ---- ping through the tunnel ----
    ok = 0
    for seq in range(1, 4):
        ident = random.getrandbits(16)
        payload = bytes(random.getrandbits(8) for _ in range(56))
        pkt = icmp_echo(my_ip, tun_peer, ident, seq, payload)
        t0 = time.perf_counter()
        s.sendto(struct.pack("!BI", PKT_DATA, sid) + xor(pkt, key), server)
        try:
            while True:
                data, _ = s.recvfrom(4096)
                typ, rsid = struct.unpack("!BI", data[:5])
                if typ != PKT_DATA:
                    continue
                reply = xor(data[5:], key)
                proto, rsrc, rdst = reply[9], socket.inet_ntoa(reply[12:16]), socket.inet_ntoa(reply[16:20])
                itype, _, _, rid, rseq = struct.unpack("!BBHHH", reply[20:28])
                if proto == 1 and itype == 0 and rid == ident and rseq == seq and reply[28:] == payload:
                    rtt = (time.perf_counter() - t0) * 1000
                    print(f"echo reply seq={seq} {rsrc}->{rdst} session={rsid} rtt={rtt:.2f} ms")
                    ok += 1
                    break
        except socket.timeout:
            print(f"FAIL: no echo reply for seq={seq}")

    s.sendto(struct.pack("!BI", PKT_BYE, sid), server)
    if ok == 3:
        print("PASS: v1 handshake + both data paths + BYE")
        return 0
    print(f"FAIL: {ok}/3 echo replies")
    return 1


if __name__ == "__main__":
    sys.exit(main())
