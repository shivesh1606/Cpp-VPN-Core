cmake_minimum_required(VERSION 3.10)
project(vpn_server)

# --- INCREMENTAL VERSIONING ---
set(PROJECT_VERSION_MAJOR 1)
set(PROJECT_VERSION_MINOR 0)

# 1. Handle Build Counter
if(NOT EXISTS "${CMAKE_SOURCE_DIR}/build_number.txt")
    file(WRITE "${CMAKE_SOURCE_DIR}/build_number.txt" "0")
endif()

file(READ "${CMAKE_SOURCE_DIR}/build_number.txt" BUILD_NUMBER)
string(STRIP "${BUILD_NUMBER}" BUILD_NUMBER)
math(EXPR BUILD_NUMBER "${BUILD_NUMBER} + 1")
file(WRITE "${CMAKE_SOURCE_DIR}/build_number.txt" "${BUILD_NUMBER}")

# 2. Get Git Hash (Optional but highly recommended)
execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

# 3. Generate Header
configure_file(
    ${CMAKE_SOURCE_DIR}/version.h.in
    ${CMAKE_BINARY_DIR}/generated/version.h
)
# ------------------------------

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -O2")

add_executable(vpn_server
    main.cpp

    net/tun/TunDevice.cpp
    net/socket/SocketManager.cpp
    sessions/client/Client_Manager.cpp
    sessions/session/ClientSession.cpp

    crypto/XorCipher.cpp
    crypto/DiffieHellman.cpp
    crypto/KeyDerivation.cpp

    protocol/Handshake.cpp

    utils/counter_definition.cpp
    utils/logger.cpp
)
option(ENABLE_PROFILING "Enable profiling instrumentation" OFF)

if(ENABLE_PROFILING)
    target_compile_definitions(vpn_server PRIVATE ENABLE_PROFILING=1)
else()
    target_compile_definitions(vpn_server PRIVATE ENABLE_PROFILING=0)
endif()

target_include_directories(vpn_server PRIVATE 
    . 
    ${CMAKE_BINARY_DIR}/generated
)

# ---------------- LD_PRELOAD shared library ----------------
# add_library(perf_hook_full SHARED
#     perf_hook_full.c
# )

# target_link_libraries(perf_hook_full
#     dl       # needed for dlsym
# )
