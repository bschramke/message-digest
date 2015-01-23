cmake_minimum_required(VERSION 3.1)

# We need C++ 11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED on)

include_directories(../library/include)

add_executable(Sample src/main.cpp)
target_link_libraries (Sample MessageDigest)