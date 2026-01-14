# CppVpn_Dump
# CppVpn_Dump

Running on aws
sudo LD_PRELOAD=~/vpn/perf_hook_full.so ~/vpn/vpn_server

sudo VPN_LOG_FILE=/var/log/vpn.log ./vpn_server


Metric Name,Direction,Path Description
RX Cost,Incoming,Internet → UDP Socket → Decryption → TUN Write → OS
TX Cost,Outgoing,OS → TUN Read → Encryption → UDP Socket → OS → Internet