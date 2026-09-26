cmake_minimum_required(VERSION 3.14)
project(PeeringIdentityPlugin LANGUAGES CXX)

if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/LogosModule.cmake")
    include(cmake/LogosModule.cmake)
else()
    message(FATAL_ERROR "LogosModule.cmake not found")
endif()

logos_module(
    NAME peering_identity
    SOURCES
        src/peering_identity_impl.h
        src/peering_identity_impl.cpp
    EXTERNAL_LIBS logos_peering
)

# What libpeering itself links.
find_package(OpenSSL 3.0 REQUIRED)
find_library(BLAKE3_LIBRARY NAMES blake3 REQUIRED)
target_link_libraries(peering_identity_module_plugin PRIVATE
    OpenSSL::SSL OpenSSL::Crypto ${BLAKE3_LIBRARY})
