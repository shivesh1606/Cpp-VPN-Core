# Unit tests: GoogleTest, discovered by CTest.
# Uses the system package (Ubuntu: libgtest-dev) when present, otherwise fetches a pinned release.
find_package(GTest QUIET)
if(NOT GTest_FOUND)
    message(STATUS "System GoogleTest not found - fetching googletest v1.14.0")
    include(FetchContent)
    FetchContent_Declare(googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
        URL_HASH SHA256=8ad598c73ad796e0d8280b082cebd82a630d73e73cd3c70057938a6501bba5d7
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

add_executable(unit_tests
    crypto/test_xor_backend.cpp
    crypto/test_cipher_registry.cpp
    crypto/test_session_lock_contract.cpp
    crypto/test_aead_kat.cpp
    crypto/test_aead_lock.cpp
    net/test_ipv4.cpp
    net/test_cidr.cpp
    config/test_ini.cpp
    config/test_node_config.cpp
    config/test_cli.cpp
    crypto/test_node_identity.cpp
    sessions/test_client_manager.cpp
    protocol/test_noise.cpp
    protocol/test_v2_wire.cpp
    protocol/test_v2_engine.cpp
)
target_link_libraries(unit_tests PRIVATE vpn_core GTest::gtest_main)
target_compile_definitions(unit_tests PRIVATE CPPVPN_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

include(GoogleTest)
gtest_discover_tests(unit_tests)
