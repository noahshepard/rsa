cmake_minimum_required(VERSION 3.15)
project(RSA)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


find_package(GTest REQUIRED)

add_library(rsa_lib
    lib/uint2048.cpp
    lib/int2048.cpp
    lib/rsa.cpp

)
target_include_directories(rsa_lib PUBLIC lib
)

add_executable(rsa_tests
    tests/uint2048_tests.cpp
    tests/rsa_tests.cpp
)

target_link_libraries(rsa_tests
    PRIVATE 
    rsa_lib 
    GTest::gtest_main
)


target_compile_options(rsa_tests PRIVATE 
    -Wall 
    -Wextra 
    -Wpedantic
    -Werror
)

include(GoogleTest)
gtest_discover_tests(rsa_tests)