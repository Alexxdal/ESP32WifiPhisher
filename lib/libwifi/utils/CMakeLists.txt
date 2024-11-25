cmake_minimum_required(VERSION 3.18)

project(libwifi_tests VERSION 0.1)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -O0")

link_directories(AFTER "/usr/local/lib")
include_directories(AFTER "/usr/local/include")

add_executable(test_misc src/helpers.c src/test_misc.c)
add_executable(test_generation src/helpers.c src/test_generation.c)
add_executable(test_parsing src/helpers.c src/test_parsing.c)
target_link_libraries(test_misc wifi)
target_link_libraries(test_generation wifi pcap)
target_link_libraries(test_parsing wifi pcap)
