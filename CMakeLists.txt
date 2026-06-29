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

# Install the binary (packaging renames it to fileengine-http-bridge).
install(TARGETS http_bridge RUNTIME DESTINATION bin)

# --- unit tests (CTest) — header-only failover circuit-breaker ---
enable_testing()
add_executable(failover_tests tests/test_failover.cpp)
target_include_directories(failover_tests PRIVATE include)
target_compile_features(failover_tests PRIVATE cxx_std_17)
add_test(NAME failover_tests COMMAND failover_tests)
