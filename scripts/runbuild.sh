# !/bin/bash
cd ~/cppVpn/DUMP
rm -rf build
mkdir build
cd build
cmake ..
make -j
