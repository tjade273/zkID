include_directories(.)

FIND_LIBRARY(JSONRPCCPP_LIBRARY_SERVER
    NAMES
    jsonrpccpp-server
    PATHS
    /usr/lib/
    /usr/local/lib
)

FIND_LIBRARY(JSONRPCCPP_LIBRARY_COMMON
    NAMES
    jsonrpccpp-common
    PATHS
    /usr/lib/
    /usr/local/lib
)

FIND_LIBRARY(JSONRPCCPP_LIBRARY_JSONCPP
    NAMES
    jsoncpp
    PATHS
    /usr/lib/
    /usr/local/lib
)

FIND_LIBRARY(JSONRPCCPP_LIBRARY_MICROHTTPD
    NAMES
    microhttpd
    PATHS
    /usr/lib/
    /usr/local/lib
)

file(GLOB_RECURSE SOURCES
    *.h
    *.cpp
    *.c)

list(REMOVE_ITEM SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/run_service.cpp)

add_library(zkid_lib ${SOURCES})

target_link_libraries(
  zkid_lib
  ${JSONRPCCPP_LIBRARY_SERVER}
  ${JSONRPCCPP_LIBRARY_COMMON}
  ${JSONRPCCPP_LIBRARY_JSONCPP}
  ${JSONRPCCPP_LIBRARY_MICROHTTPD}
  snark
)

target_include_directories(
  zkid_lib
  
  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)