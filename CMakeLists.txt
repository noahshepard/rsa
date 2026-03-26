cmake_minimum_required(VERSION 3.15)
project(RSA)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


find_package(GTest REQUIRED)

add_library(int_lib INTERFACE)
target_include_directories(int_lib INTERFACE lib)


add_library(rsa_lib
    lib/rsa.cpp
)
target_link_libraries(rsa_lib PRIVATE int_lib)
target_include_directories(rsa_lib PUBLIC src)


add_executable(rsa_tests
    tests/rsa_tests.cpp
    tests/uint_tests.cpp
)

target_link_libraries(rsa_tests
    PRIVATE 
    int_lib
    rsa_lib
    GTest::gtest_main
)

target_compile_options(rsa_tests PRIVATE 
    -Wall 
    -Wextra 
    -Wpedantic
    -Werror
    -fsanitize=address -g
)

target_link_options(rsa_tests PRIVATE -fsanitize=address)

add_executable(rsa_app 
    src/main.cpp
)

target_compile_options(rsa_app PRIVATE 
    -Wall 
    -Wextra 
    -Wpedantic
    -Werror
    -fsanitize=address -g
)

target_link_libraries(rsa_app
    PRIVATE
    int_lib
    rsa_lib
)

target_link_options(rsa_app PRIVATE -fsanitize=address)

include(GoogleTest)
gtest_discover_tests(rsa_tests)