#!/bin/bash
# Experiment 001: builds pkt_bench.c against a locally unpacked Ubuntu libsodium package
# (no root needed) and runs it twice pinned to one core, plus an -O3 XOR reference run.
# Usage: bash run.sh | tee results/<YYYY-MM-DD>_<host>_<env>.txt
set -e
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HOME/cppvpn-bench}"
CPU="${CPU:-2}"
mkdir -p "$WORK" && cd "$WORK"
rm -rf root && mkdir root
ls libsodium-dev_*.deb >/dev/null 2>&1 || apt-get download libsodium-dev libsodium23 >/dev/null
for d in ./*.deb; do dpkg -x "$d" root; done
cp "$SRC_DIR/pkt_bench.c" .
LIB=$(ls root/usr/lib/*/libsodium.a | head -1)
gcc -O2 -I root/usr/include pkt_bench.c "$LIB" -o pkt_bench
gcc -O3 -I root/usr/include pkt_bench.c "$LIB" -o pkt_bench_o3

echo "date:     $(date -Iseconds)"
echo "host:     $(hostname)  $(uname -srm)"
echo "cpu:      $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs)"
echo "compiler: $(gcc --version | head -1)"
echo "sodium:   $(grep -m1 SODIUM_VERSION_STRING root/usr/include/sodium/version.h | awk '{print $3}') (static)"
for run in 1 2; do echo "=== run $run (-O2, pinned to cpu $CPU) ==="; taskset -c "$CPU" ./pkt_bench; done
echo "=== reference: XOR at -O3 (pinned to cpu $CPU) ==="
taskset -c "$CPU" ./pkt_bench_o3 | grep -E "payload|xor"
