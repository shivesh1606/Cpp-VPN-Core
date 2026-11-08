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

# ---------------- Engine library (shared by vpn_server and unit tests) ----------------
add_library(vpn_core STATIC
    net/tun/TunDevice.cpp
    net/socket/SocketManager.cpp
    sessions/client/Client_Manager.cpp
    sessions/session/ClientSession.cpp

    config/Ini.cpp
    config/NodeConfig.cpp
    config/Cli.cpp

    crypto/CipherRegistry.cpp
    crypto/NodeIdentity.cpp
    crypto/backends/XorBackend.cpp
    crypto/backends/SodiumAead.cpp
    crypto/DiffieHellman.cpp
    crypto/KeyDerivation.cpp

    protocol/Handshake.cpp

    utils/counter_definition.cpp
    utils/logger.cpp
)

option(ENABLE_PROFILING "Enable profiling instrumentation" OFF)

if(ENABLE_PROFILING)
    target_compile_definitions(vpn_core PUBLIC ENABLE_PROFILING=1)
else()
    target_compile_definitions(vpn_core PUBLIC ENABLE_PROFILING=0)
endif()

target_include_directories(vpn_core PUBLIC
    .
    ${CMAKE_BINARY_DIR}/generated
)

# ---------------- Crypto libraries (design doc 01, section 2) ----------------
# libsodium is required (AEAD now, X25519/BLAKE2b/Ed25519 from M4). The static archive is
# preferred so vpn_server has no runtime dependency on libsodium.so.
# Ubuntu/Debian: apt-get install libsodium-dev. Elsewhere: -DCMAKE_PREFIX_PATH=<prefix>.
find_package(Threads REQUIRED)
find_path(SODIUM_INCLUDE_DIR sodium.h)
find_library(SODIUM_LIBRARY NAMES libsodium.a sodium)
if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "libsodium not found: install libsodium-dev or set CMAKE_PREFIX_PATH")
endif()
message(STATUS "libsodium: ${SODIUM_LIBRARY}")
target_include_directories(vpn_core PUBLIC ${SODIUM_INCLUDE_DIR})
target_link_libraries(vpn_core PUBLIC ${SODIUM_LIBRARY} Threads::Threads)

# Optional second implementation of the same algorithms, for benchmarks (experiment 002) and
# the cross-implementation test. Selecting it at runtime comes with node.conf (M3).
option(WITH_OPENSSL "Also build OpenSSL AEAD backends" OFF)
if(WITH_OPENSSL)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    find_package(OpenSSL 1.1 REQUIRED COMPONENTS Crypto)
    message(STATUS "OpenSSL backends: ON (${OPENSSL_VERSION}, ${OPENSSL_CRYPTO_LIBRARY})")
    target_sources(vpn_core PRIVATE crypto/backends/OpenSslAead.cpp)
    target_compile_definitions(vpn_core PUBLIC CPPVPN_WITH_OPENSSL=1)
    target_link_libraries(vpn_core PUBLIC OpenSSL::Crypto ${CMAKE_DL_LIBS})
else()
    target_compile_definitions(vpn_core PUBLIC CPPVPN_WITH_OPENSSL=0)
endif()

# ---------------- Server ----------------
add_executable(vpn_server main.cpp)
target_link_libraries(vpn_server PRIVATE vpn_core)

# ---------------- Crypto benchmark (design doc 01, section 5; experiment 002) ----------------
string(TOUPPER "${CMAKE_BUILD_TYPE}" _bt)
add_executable(crypto_bench tools/crypto_bench.cpp)
target_link_libraries(crypto_bench PRIVATE vpn_core)
target_compile_definitions(crypto_bench PRIVATE
    CPPVPN_BUILD_FLAGS="${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${_bt}}"
    CPPVPN_BUILD_TYPE="${CMAKE_BUILD_TYPE}")

# ---------------- Unit tests (GoogleTest, run with ctest) ----------------
include(CTest)   # defines BUILD_TESTING (default ON)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

# ---------------- LD_PRELOAD shared library ----------------
# add_library(perf_hook_full SHARED
#     perf_hook_full.c
# )

# target_link_libraries(perf_hook_full
#     dl       # needed for dlsym
# )
