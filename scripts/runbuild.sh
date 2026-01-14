# !/bin/bash
cd ~/cppVpn/DUMP
rm -rf build
mkdir build
cd build
cmake -DENABLE_PROFILING=ON ..
make -j
