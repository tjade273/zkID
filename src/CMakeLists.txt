include_directories(.)

file(GLOB_RECURSE SOURCES
    *.h
    *.cpp
    *.c)


add_library(our_lib ${SOURCES})

target_link_libraries(
  our_lib
  snark
)

target_include_directories(
  our_lib
  
  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
