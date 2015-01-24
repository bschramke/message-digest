project(message-digest)
cmake_minimum_required(VERSION 2.8)

# Append our module directory to CMake
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

add_subdirectory(library)
add_subdirectory(sample)
add_subdirectory(test)