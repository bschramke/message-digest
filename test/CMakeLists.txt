cmake_minimum_required(VERSION 2.8)
set(TESTUNIT "MessageDigest-testrunner")

# We need C++ 11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED on)

# Sources
set(TEST_SRCS src/main.cpp src/MessageDigestCRC32Test.cpp src/MessageDigestMD5Test.cpp src/MessageDigestSHA1Test.cpp src/MessageDigestTest.cpp )

include_directories(src)
include_directories(../library/include)

find_package(CppUnit)
add_executable( ${TESTUNIT} ${TEST_SRCS})
add_test(NAME MessageDigest WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR} COMMAND ${TESTUNIT} -all)
target_link_libraries (${TESTUNIT} MessageDigest cppunit)