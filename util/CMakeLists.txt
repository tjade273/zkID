include_directories(.)

file(GLOB_RECURSE UTIL_SOURCES
    *.h
    *.cpp
    *.c)

target_sources(zkid_lib PUBLIC ${UTIL_SOURCES})