# CppVpn_Dump
🚀 Minimal Layer-3 UDP VPN (C++ / TUN Interface)

This project implements a very small, custom VPN server using:

Linux TUN interface (L3 IP tunneling)

UDP transport

AES-based encryption layer (pluggable)

Client Manager for assigning internal VPN IPs

Routing logic for

UDP → TUN (client → internet)

TUN → UDP (internet → client)

It is designed to work with an Android VPN client where the client has a fixed TUN IP (e.g., 10.8.0.2) and the server assigns its own internal VPN IP (e.g., 10.8.0.10).

📌 Features
🔹 Server-side Features

Creates and manages TUN device (tun0)

Receives encrypted packets from client over UDP

Decrypts → rewrites source IP → fixes checksum → forwards into TUN

Reads packets from TUN → rewrites destination IP → encrypts → sends to correct client

Supports multiple simultaneous clients

Allocates internal VPN IPs dynamically (10.8.0.10 onward)

Fast lookup:

UDP → VPN IP

VPN IP → Client

🔹 Client-side assumptions

Your Android app:

Always uses the same TUN IP (e.g., 10.8.0.2)

Encrypts packets before sending to server

Expects encrypted packets back

🧠 Architecture
Internal IP model
Android device
   |
   | Android TUN IP: 10.8.0.2  (fixed)
   |
VPN Server
   |
   | Server-assigned VPN IP: 10.8.0.X (unique)
   |
Internet


The server rewrites IP headers:

Direction	Rewrite
UDP → TUN	Replace src IP with server-assigned VPN IP
TUN → UDP	Replace dst IP with Android’s fixed TUN IP
🔄 Packet Flow Diagram (Simple)
1. Client → Server → Internet
[Android App]
       |
       v  (Encrypted UDP)
[Server: UDP socket]
       |
       v  decrypt()
[IP packet]
       |
       | overwrite src_ip = 10.8.0.X
       v
[write → TUN]
       |
       v
[Linux routing → Internet]

2. Internet → Server → Client
[Packet arrives to tun0]
       |
       v
extract dst_ip = 10.8.0.X
find client X
overwrite dst_ip = 10.8.0.2
encrypt()
       |
       v
sendto(udp_addr)

📁 Project Structure
.
├── server.cpp
├── Client_Manager.h
├── Client_Manager.cpp
├── Encryption.h
├── Encryption.cpp
├── README.md

🛠️ Build Instructions
✅ Requirements

You must be on Linux because TUN devices only work there.

Install dependencies:

sudo apt update
sudo apt install g++ make cmake linux-headers-$(uname -r)

🔧 Build using g++

Example:

g++ server.cpp Client_Manager.cpp Encryption.cpp -o vpn_server


Or with all warnings:

g++ -Wall -Wextra server.cpp Client_Manager.cpp Encryption.cpp -o vpn_server

▶️ Run Instructions
1. Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1


To persist:

echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf

2. Start your VPN backend
sudo ./vpn_server

3. Add routing rules (example)

Send all VPN traffic to internet:

sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE

⚙️ How the Server Manages Clients
1. UDP → VPN IP mapping

udp_to_vpn["49.23.92.19:55221"] = 10.8.0.10

2. VPN IP → Client structure mapping

vpn_to_client[10.8.0.10] → struct { android_ip, udp_addr }

3. IP allocation

baseIp = 10.8.0.10

Pool size (example): 100
Allocates sequentially:

10.8.0.10
10.8.0.11
10.8.0.12
...

🧪 Debugging
View packets:
sudo tcpdump -i any udp port 5555 -vv

View TUN traffic:
sudo tcpdump -i tun0 -n

❗ Troubleshooting
❌ "open /dev/net/tun: No such file"

Create tun driver:

sudo modprobe tun

❌ No internet access inside VPN

Check:

sudo iptables -t nat -L -n -v


Ensure MASQUERADE rule exists.

❌ Packets stuck at Android

Most common issues:

Wrong source/destination IP rewrite

Checksum not recalculated

Encryption mismatch

🧩 Future Improvements

Add proper IPv4 header checksum helper

Add TCP MSS rewrite

Add session timeout

Add DH key exchange

Add proper login/authentication

Add multi-threading (IO threads)

✔️ READY TO USE

This README gives complete info:
✓ Architecture
✓ Packet flow
✓ Build instructions
✓ Linux setup
✓ Routing
✓ Debugging
✓ Future improvements