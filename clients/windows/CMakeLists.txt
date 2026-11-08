cmake_minimum_required(VERSION 3.10)
project(vpn_client_windows CXX)

if(NOT WIN32)
    message(FATAL_ERROR "This target is Windows-only. Build the Linux server from the root CMakeLists.txt.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Protocol v2 code shared with the server (design doc 02): Noise IK, v2 wire format, initiator
# engine and the cipher backends. Portable sources only (no Linux headers).
set(REPO_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
set(SHARED_V2_SOURCES
    ${REPO_ROOT}/protocol/noise/Noise.cpp
    ${REPO_ROOT}/protocol/v2/Wire.cpp
    ${REPO_ROOT}/protocol/v2/Client.cpp
    ${REPO_ROOT}/crypto/CipherRegistry.cpp
    ${REPO_ROOT}/crypto/Base64Url.cpp
    ${REPO_ROOT}/crypto/backends/XorBackend.cpp
    ${REPO_ROOT}/crypto/backends/SodiumAead.cpp
)

# libsodium (MSYS2: pacman -S mingw-w64-x86_64-libsodium). Static, so the exe needs no DLL.
find_path(SODIUM_INCLUDE_DIR sodium.h)
find_library(SODIUM_LIBRARY NAMES libsodium.a sodium)
if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "libsodium not found: pacman -S mingw-w64-x86_64-libsodium")
endif()

add_executable(vpn_client main.cpp ${SHARED_V2_SOURCES})

target_include_directories(vpn_client PRIVATE . ${REPO_ROOT} ${SODIUM_INCLUDE_DIR})
target_compile_definitions(vpn_client PRIVATE WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00
    CPPVPN_WITH_OPENSSL=0 SODIUM_STATIC=1)

target_link_libraries(vpn_client PRIVATE ${SODIUM_LIBRARY} ws2_32 iphlpapi ntdll advapi32)

if(MINGW)
    # -Wno-unknown-pragmas: vendored wintun.h uses MSVC-only '#pragma warning'
    target_compile_options(vpn_client PRIVATE -Wall -Wextra -Wno-unknown-pragmas -O2)
    # Static runtime so vpn_client.exe runs outside the MSYS2 shell (no libstdc++/libgcc DLLs)
    target_link_options(vpn_client PRIVATE -static -static-libgcc -static-libstdc++)
endif()

# Copy wintun.dll (WireGuard LLC, signed, v0.14.1) next to the built executable
add_custom_command(TARGET vpn_client POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/wintun.dll"
        "$<TARGET_FILE_DIR:vpn_client>/wintun.dll"
    COMMENT "Copying wintun.dll to output directory"
)
