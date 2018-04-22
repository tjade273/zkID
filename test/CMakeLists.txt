find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})
include_directories(.)

add_executable(
  run_tests
  run_tests.cpp
)

FILE (GLOB_RECURSE res "res/*.*")
foreach(resource ${res})
 get_filename_component(filename ${resource} NAME)
 get_filename_component(dir ${resource} DIRECTORY)
 get_filename_component(dirname ${dir} NAME)
 
 set (output "")
 
 while(NOT ${dirname} STREQUAL res)
  get_filename_component(path_component ${dir} NAME)
  set (output "${path_component}/${output}")
  get_filename_component(dir ${dir} DIRECTORY)
  get_filename_component(dirname ${dir} NAME)
 endwhile()
 
 set(output "${CMAKE_CURRENT_BINARY_DIR}/res/${filename}")
 
 add_custom_command(
  COMMENT "Moving updated resource-file '${filename}'"
  OUTPUT ${output}
  DEPENDS ${resource}
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
  ${resource}
  ${output}
 )
 add_custom_target(${filename} ALL DEPENDS ${resource} ${output})
endforeach()

target_link_libraries(
  run_tests
  gtest
  snark
)
target_include_directories(
  run_tests

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)