cmake_minimum_required(VERSION 3.9.0)
project(openssl-key-exchange VERSION 0.0.1)

add_subdirectory(deps/rpclib)

find_package(OpenSSL REQUIRED)
find_package(Protobuf REQUIRED)

message(STATUS "openssl libs: ${OPENSSL_LIBRARIES}")
message(STATUS "protobuf libs: ${PROTOBUF_LIBRARIES}")

set(SOURCES
src/crypto.cc
)

include_directories(
src/
${CMAKE_BINARY_DIR}/
${OpenSSL_INCLUDE_DIR}/
${Protobuf_INCLUDE_DIR}/
deps/rpclib/include/
)

set(PROTO_FILES
protos/key_exchange.proto
)
PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})


SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} --std=c++11")

add_executable(server  src/server.cc ${SOURCES} ${PROTO_SRCS})
target_link_libraries(server rpc ${OPENSSL_LIBRARIES} ${PROTOBUF_LIBRARIES} pthread)

add_executable(client  src/client.cc ${SOURCES} ${PROTO_SRCS})
target_link_libraries(client rpc ${OPENSSL_LIBRARIES} ${PROTOBUF_LIBRARIES} pthread)

add_executable(ecdsa-test  src/ecdsa-test.cc ${SOURCES} ${PROTO_SRCS})
target_link_libraries(ecdsa-test ${OPENSSL_LIBRARIES} ${PROTOBUF_LIBRARIES})
