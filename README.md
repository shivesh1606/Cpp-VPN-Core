# CppVpn_Dump
# CppVpn_Dump

Running on aws
sudo LD_PRELOAD=~/vpn/perf_hook_full.so ~/vpn/vpn_server

sudo VPN_LOG_FILE=/var/log/vpn.log ./vpn_server


Metric Name,Direction,Path Description
RX Cost,Incoming,Internet → UDP Socket → Decryption → TUN Write → OS
TX Cost,Outgoing,OS → TUN Read → Encryption → UDP Socket → OS → Internet


3. Disable Nagle-like behavior in the Kernel
Since you are doing high-speed video, you want the Linux kernel to prioritize your UDP packets. Run these commands on your EC2 server to optimize the network stack for VPN traffic:
# Increase default socket memory
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.wmem_max=26214400
# Reduce the time packets sit in the queue
sudo sysctl -w net.core.netdev_max_backlog=2000