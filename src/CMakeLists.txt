include_directories(.)

FIND_LIBRARY(JSONRPCCPP_LIBRARIES
    NAMES
    jsonrpccpp-common
    jsonrpccpp-client
    jsonrpccpp-server
    json-rpc-cpp-common
    json-rpc-cpp-client
    json-rpc-cpp-server
    PATHS
    /usr/lib/
    /usr/local/lib
)

FIND_LIBRARY(JSONCPP_LIBRARIES
    NAMES
    jsoncpp
    PATHS
    /usr/lib/
    /usr/local/lib
)

file(GLOB_RECURSE SOURCES
    *.h
    *.cpp
    *.c)

add_library(zkid_lib ${SOURCES})


target_link_libraries(
  zkid_lib
  ${JSONRPCCPP_LIBRARIES}
  ${JSONCPP_LIBRARIES}
  snark
)

target_include_directories(
  zkid_lib
  
  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)