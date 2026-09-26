cmake_minimum_required(VERSION 3.20)
project(logos_peering VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(LOGOS_PEERING_BUILD_TESTS "Build libpeering's unit tests" ON)

find_package(OpenSSL 3.0 REQUIRED)
find_package(nlohmann_json 3.10 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(BLAKE3 REQUIRED IMPORTED_TARGET libblake3)

add_library(logos_peering STATIC
    lib/src/audit.cpp
    lib/src/certs.cpp
    lib/src/crypto.cpp
    lib/src/discovery_key.cpp
    lib/src/enrollment.cpp
    lib/src/fs.cpp
    lib/src/identity.cpp
    lib/src/invites.cpp
    lib/src/names.cpp
    lib/src/pairing.cpp
    lib/src/tickets.cpp
)
add_library(logos::peering ALIAS logos_peering)
target_include_directories(logos_peering PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/lib/include>
    $<INSTALL_INTERFACE:include>)
target_link_libraries(logos_peering PUBLIC
    OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json PkgConfig::BLAKE3)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(logos_peering PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(LOGOS_PEERING_BUILD_TESTS)
    enable_testing()
    find_package(GTest REQUIRED)
    add_executable(logos_peering_tests
        lib/tests/test_audit.cpp
        lib/tests/test_certs.cpp
        lib/tests/test_crypto.cpp
        lib/tests/test_discovery_key.cpp
        lib/tests/test_enrollment.cpp
        lib/tests/test_identity.cpp
        lib/tests/test_invites.cpp
        lib/tests/test_names.cpp
        lib/tests/test_pairing.cpp
        lib/tests/test_tickets.cpp
    )
    target_link_libraries(logos_peering_tests PRIVATE logos_peering GTest::gtest_main)
    include(GoogleTest)
    gtest_discover_tests(logos_peering_tests DISCOVERY_TIMEOUT 60)
endif()

include(GNUInstallDirs)
install(TARGETS logos_peering EXPORT logos_peering_targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY lib/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
