include_directories("${PROJECT_SOURCE_DIR}/src")
add_executable(exec_sh_test exec_sh_test.c)
target_link_libraries(exec_sh_test aosc)
