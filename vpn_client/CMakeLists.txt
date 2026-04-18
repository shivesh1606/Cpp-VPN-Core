add_executable(vpn_client
    vpn_client.cpp
    ../net/tun/TunDevice.cpp
    ../net/socket/SocketManager.cpp
    ../crypto/XorCipher.cpp
    ../crypto/DiffieHellman.cpp
    ../utils/logger.cpp
)

target_include_directories(vpn_client PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_BINARY_DIR}/generated
)

if(MSVC)
    target_compile_options(vpn_client PRIVATE /W3 /O2)
else()
    target_compile_options(vpn_client PRIVATE -Wall -Wextra -O2)
endif()

target_compile_definitions(vpn_client PRIVATE
    $<$<BOOL:${ENABLE_PROFILING}>:ENABLE_PROFILING=1>
    $<$<NOT:$<BOOL:${ENABLE_PROFILING}>>:ENABLE_PROFILING=0>
)
