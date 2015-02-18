cmake_minimum_required(VERSION 2.8)
set(LIBNAME "MessageDigest")

# We need C++ 11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED on)

# Sources
set(MessageDigest_SRCS  src/MessageDigest.cpp 
                        src/MessageDigestCRC32.cpp
                        src/MessageDigestMD5.cpp
                        src/MessageDigestSHA1.cpp
                        src/MessageDigestSHA2.cpp
                        src/MessageDigestSHA224.cpp
                        src/MessageDigestSHA256.cpp
)

include_directories(include)

add_library( "${LIBNAME}" SHARED ${MessageDigest_SRCS})