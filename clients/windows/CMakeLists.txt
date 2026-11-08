cmake_minimum_required(VERSION 3.10)
project(vpn_client_windows CXX)

if(NOT WIN32)
    message(FATAL_ERROR "This target is Windows-only. Build the Linux server from the root CMakeLists.txt.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(vpn_client main.cpp)

target_include_directories(vpn_client PRIVATE .)
target_compile_definitions(vpn_client PRIVATE WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00)

target_link_libraries(vpn_client PRIVATE ws2_32 iphlpapi ntdll advapi32)

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
