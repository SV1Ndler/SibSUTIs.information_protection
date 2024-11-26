include(CompileOptions)


set(target_name crypto-utils)

add_library(
  ${target_name}
  STATIC
)

target_sources(
  ${target_name}
  PRIVATE
    crypto-utils.cpp
)

target_include_directories(
  ${target_name}
  PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
)

set_compile_options(${target_name})


#TEST
set(test_target_name "${target_name}_test")

add_executable(${test_target_name})

target_sources(
  ${test_target_name}
  PRIVATE
    crypto-utils.test.cpp
)

target_link_libraries(
  ${test_target_name}
  PRIVATE
    ${target_name}
    gtest
    gtest_main
)

set_compile_options(${target_name})

add_test(
  NAME ${test_target_name}
  COMMAND ${test_target_name}
)