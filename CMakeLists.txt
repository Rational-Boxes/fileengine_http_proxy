cmake_minimum_required(VERSION 3.15)
project(http_bridge)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Default to Debug for local dev, but let packaging pass -DCMAKE_BUILD_TYPE=Release.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(gRPC CONFIG REQUIRED)
# Module mode: Fedora ships no ProtobufConfig.cmake; the module still provides
# the protobuf::libprotobuf target.
find_package(Protobuf REQUIRED)
find_package(Poco COMPONENTS Foundation Util Net NetSSL Crypto JSON REQUIRED)

# OpenLDAP. Fedora's openldap-devel ships no pkg-config (.pc) file, so locate
# the headers and the ldap/lber libraries directly.
find_path(LDAP_INCLUDE_DIR ldap.h)
find_library(LDAP_LIBRARY NAMES ldap)
find_library(LBER_LIBRARY NAMES lber)
if(NOT LDAP_INCLUDE_DIR OR NOT LDAP_LIBRARY)
    message(FATAL_ERROR "OpenLDAP development files not found (install openldap-devel)")
endif()
set(LDAP_LIBRARIES ${LDAP_LIBRARY} ${LBER_LIBRARY})

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${LDAP_INCLUDE_DIR})

# Generate gRPC/protobuf code from the canonical proto.
set(proto_path ${CMAKE_CURRENT_SOURCE_DIR}/proto)
set(proto_file ${proto_path}/fileservice.proto)
set(proto_srcs_dir ${CMAKE_CURRENT_BINARY_DIR}/proto/src)
set(proto_hdrs_dir ${CMAKE_CURRENT_BINARY_DIR}/proto/include)
file(MAKE_DIRECTORY ${proto_srcs_dir})
file(MAKE_DIRECTORY ${proto_hdrs_dir})
add_custom_command(
    OUTPUT ${proto_srcs_dir}/fileservice.pb.cc ${proto_hdrs_dir}/fileservice.pb.h
           ${proto_srcs_dir}/fileservice.grpc.pb.cc ${proto_hdrs_dir}/fileservice.grpc.pb.h
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/generate_grpc.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${proto_file}
    COMMENT "Generating gRPC code for FileService"
)
include_directories(${proto_hdrs_dir})
set(PROTO_SRCS
    ${proto_srcs_dir}/fileservice.pb.cc
    ${proto_srcs_dir}/fileservice.grpc.pb.cc
)

add_executable(http_bridge
    src/main.cpp
    src/http_server.cpp
    src/http_client.cpp
    src/oauth_provider.cpp
    src/grpc_client_wrapper.cpp
    src/ldap_authenticator.cpp
    src/audit_publisher.cpp
    src/session_store.cpp
    src/utils.cpp
    ${PROTO_SRCS}
)

target_link_libraries(http_bridge
    gRPC::grpc++
    gRPC::grpc
    protobuf::libprotobuf
    Poco::Net
    Poco::NetSSL
    Poco::Crypto
    Poco::Util
    Poco::JSON
    Poco::Foundation
    ${LDAP_LIBRARIES}
    Threads::Threads
)

# Optional hiredis for durable audit emission (login_success/login_failure ->
# fileengine:audit). Without it the audit publisher compiles as a no-op, so the
# bridge still builds. Mirrors file_engine_core's FILEENGINE_ENABLE_EVENTS block.
find_library(HIREDIS_LIB hiredis)
find_path(HIREDIS_INC hiredis/hiredis.h)
if(HIREDIS_LIB AND HIREDIS_INC)
    target_compile_definitions(http_bridge PRIVATE HTTPBRIDGE_HAS_HIREDIS=1)
    target_include_directories(http_bridge PRIVATE ${HIREDIS_INC})
    target_link_libraries(http_bridge ${HIREDIS_LIB})
    message(STATUS "http_bridge audit emission ENABLED (hiredis: ${HIREDIS_LIB})")
else()
    message(WARNING "hiredis not found; http_bridge audit emission compiled out")
endif()

# Install the binary (packaging renames it to fileengine-http-bridge).
install(TARGETS http_bridge RUNTIME DESTINATION bin)

# ---------------------------------------------------------------------------
# Unit tests (CTest)
# ---------------------------------------------------------------------------
enable_testing()
find_package(GTest REQUIRED)

# gtest suite over the pure utilities in src/utils.cpp (tenant parsing, string
# helpers, URL codec, RFC 2617 Digest helpers). These need no gRPC/LDAP, so the
# target links only utils.cpp + Poco::Foundation.
add_executable(http_tests
    tests/test_main.cpp
    tests/test_utils.cpp
    src/utils.cpp
)
target_include_directories(http_tests PRIVATE include)
target_link_libraries(http_tests
    Poco::Foundation
    Threads::Threads
    GTest::gtest
)
add_test(NAME http_tests COMMAND http_tests)

# --- header-only failover circuit-breaker ---
add_executable(failover_tests tests/test_failover.cpp)
target_include_directories(failover_tests PRIVATE include)
target_compile_features(failover_tests PRIVATE cxx_std_17)
add_test(NAME failover_tests COMMAND failover_tests)

# --- security regression suite over the header-only HS256 JWT (jwt.h) ---
# Header-only: links only Poco (JSON/Foundation) + OpenSSL (HMAC) + GTest.
add_executable(security_tests tests/test_main.cpp tests/test_security.cpp)
target_include_directories(security_tests PRIVATE include)
target_compile_features(security_tests PRIVATE cxx_std_17)
target_link_libraries(security_tests
    Poco::JSON
    Poco::Net         # Poco::Net::IPAddress for client_ip.h (trusted-proxy resolution)
    Poco::Crypto      # transitively links OpenSSL libcrypto for jwt.h's HMAC()
    Poco::Foundation
    Threads::Threads
    GTest::gtest
)
add_test(NAME security_tests COMMAND security_tests)
