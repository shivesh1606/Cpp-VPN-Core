cmake_minimum_required(VERSION 3.10)
project(vpn_server)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -O2")

add_executable(vpn_server
    main.cpp

    net/tun/TunDevice.cpp

    sessions/client/Client_Manager.cpp
    sessions/session/ClientSession.cpp

    crypto/XorCipher.cpp
    crypto/DiffieHellman.cpp
    crypto/KeyDerivation.cpp

    protocol/Handshake.cpp
)

target_include_directories(vpn_server PRIVATE
    .
)
