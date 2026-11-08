#!/bin/bash
# Experiment 002: build crypto_bench from the repo (libsodium + OpenSSL backends) and run it
# pinned to one core. Prints a machine summary first, so the output file is self-describing.
#
# Usage (from anywhere):  bash experiments/002-crypto-bench-backends/run.sh | tee <results file>
# Env:
#   BUILD_TYPE   CMake build type (default Release = Docker image flags; "" = scripts/runbuild.sh flags)
#   CPU          core to pin to (default 0)
#   COUNT, RUNS  passed to crypto_bench (default 1000000, 3)
#   WORK         build directory (default ~/cppvpn-exp002)
#   PREFIX       extra CMAKE_PREFIX_PATH (e.g. a locally unpacked libsodium-dev)
# Needs: cmake, g++, libsodium-dev, libssl-dev  (Ubuntu: sudo apt-get install -y cmake g++ libsodium-dev libssl-dev)
set -e
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD_TYPE="${BUILD_TYPE-Release}"
CPU="${CPU:-0}"
COUNT="${COUNT:-1000000}"
RUNS="${RUNS:-3}"
WORK="${WORK:-$HOME/cppvpn-exp002}"

# Configure in a copy: CMake increments build_number.txt in the source tree.
rm -rf "$WORK/src" && mkdir -p "$WORK/src"
(cd "$REPO" && tar --exclude=./build --exclude=./.git -cf - .) | (cd "$WORK/src" && tar -xf -)
cmake -S "$WORK/src" -B "$WORK/build" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DWITH_OPENSSL=ON \
      -DBUILD_TESTING=OFF ${PREFIX:+-DCMAKE_PREFIX_PATH="$PREFIX"} >/dev/null
cmake --build "$WORK/build" --target crypto_bench -j"$(nproc)" >/dev/null

echo "# ---- machine ----"
echo "# repo commit: $(git -C "$REPO" describe --always --dirty 2>/dev/null || echo unknown)"
lscpu 2>/dev/null | grep -E "^(Architecture|Model name|CPU\(s\)|Thread|Core|Socket|CPU max MHz|Hypervisor vendor|Virtualization type)" | sed 's/^/# /'
grep -qw aes /proc/cpuinfo && echo "# cpu flags: aes" || echo "# cpu flags: no 'aes' flag"
echo "# pinned to cpu $CPU"
echo
taskset -c "$CPU" "$WORK/build/crypto_bench" --count "$COUNT" --runs "$RUNS"
