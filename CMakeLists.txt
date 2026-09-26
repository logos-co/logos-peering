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
# The service speaks tls_tcp through the lp_* C ABI; the image that embeds it
# links the plain runtime.
find_package(logos-protocol CONFIG REQUIRED)

add_library(logos_peering STATIC
    lib/src/audit.cpp
    lib/src/callers.cpp
    lib/src/certs.cpp
    lib/src/config.cpp
    lib/src/crypto.cpp
    lib/src/discovery_key.cpp
    lib/src/enrollment.cpp
    lib/src/facade.cpp
    lib/src/fs.cpp
    lib/src/identity.cpp
    lib/src/invite_store.cpp
    lib/src/invites.cpp
    lib/src/local_identity.cpp
    lib/src/names.cpp
    lib/src/pairing.cpp
    lib/src/pairing_session.cpp
    lib/src/routes.cpp
    lib/src/service.cpp
    lib/src/tickets.cpp
)
add_library(logos::peering ALIAS logos_peering)
set_target_properties(logos_peering PROPERTIES EXPORT_NAME peering)
target_include_directories(logos_peering PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/lib/include>
    $<INSTALL_INTERFACE:include>)
target_link_libraries(logos_peering PUBLIC
    OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json PkgConfig::BLAKE3
    logos-protocol::logos_protocol_plain)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(logos_peering PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(LOGOS_PEERING_BUILD_TESTS)
    enable_testing()
    find_package(GTest REQUIRED)
    add_executable(logos_peering_tests
        lib/tests/test_audit.cpp
        lib/tests/test_callers.cpp
        lib/tests/test_certs.cpp
        lib/tests/test_config.cpp
        lib/tests/test_crypto.cpp
        lib/tests/test_discovery_key.cpp
        lib/tests/test_enrollment.cpp
        lib/tests/test_identity.cpp
        lib/tests/test_invite_store.cpp
        lib/tests/test_invites.cpp
        lib/tests/test_names.cpp
        lib/tests/test_pairing.cpp
        lib/tests/test_pairing_session.cpp
        lib/tests/test_routes.cpp
        lib/tests/test_service.cpp
        lib/tests/test_tickets.cpp
    )
    target_link_libraries(logos_peering_tests PRIVATE logos_peering GTest::gtest_main)
    include(GoogleTest)
    gtest_discover_tests(logos_peering_tests DISCOVERY_TIMEOUT 60)
endif()

# The facade host, when logos-module-loader-qt's package (its host process
# library) is given.
set(LOGOS_MODULE_LOADER_QT_ROOT "" CACHE PATH "logos-module-loader-qt package, for logos_host_remote")
if(LOGOS_MODULE_LOADER_QT_ROOT)
    add_executable(logos_host_remote host/logos_host_remote.cpp)
    target_include_directories(logos_host_remote PRIVATE
        ${LOGOS_MODULE_LOADER_QT_ROOT}/include/logos_module_loader_qt)
    target_link_libraries(logos_host_remote PRIVATE
        logos_peering
        ${LOGOS_MODULE_LOADER_QT_ROOT}/lib/liblogos_host_process.a
        logos-protocol::logos_protocol_plain)
    install(TARGETS logos_host_remote RUNTIME DESTINATION bin)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
install(TARGETS logos_peering EXPORT logos_peering_targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY lib/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
# find_package(logos_peering): the logos::peering target and what it links.
install(EXPORT logos_peering_targets NAMESPACE logos::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/logos_peering)
configure_package_config_file(cmake/logos_peeringConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/logos_peeringConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/logos_peering)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/logos_peeringConfigVersion.cmake
    COMPATIBILITY SameMinorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/logos_peeringConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/logos_peeringConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/logos_peering)
