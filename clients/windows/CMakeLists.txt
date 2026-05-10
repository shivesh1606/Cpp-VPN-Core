cmake_minimum_required(VERSION 3.10)
project(vpn_client_windows)

if(NOT WIN32)
    message(FATAL_ERROR "This target is Windows-only. Build the Linux server from the root CMakeLists.txt.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(vpn_client main.cpp)

target_include_directories(vpn_client PRIVATE .)

target_link_libraries(vpn_client PRIVATE
    ws2_32
    iphlpapi
)

# Copy wintun.dll next to the built executable automatically
add_custom_command(TARGET vpn_client POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/wintun.dll"
        "$<TARGET_FILE_DIR:vpn_client>/wintun.dll"
    COMMENT "Copying wintun.dll to output directory"
)
