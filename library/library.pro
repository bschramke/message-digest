QT       -= core gui

TARGET = MessageDiggest
TEMPLATE = lib
VERSION = 0.0.1

DEFINES += LIBRARY_MESSAGE_DIGEST

QMAKE_CXXFLAGS += -std=c++11

INCLUDEPATH = $$PWD/include/

SOURCES += \
    src/MessageDigest.cpp \
    src/MessageDigestCRC32.cpp \
    src/MessageDigestMD5.cpp \
    src/MessageDigestSHA1.cpp

HEADERS += \
    include/MessageDigest/MessageDigest.hpp \
    include/MessageDigest/MessageDigestImpl.hpp \
    include/MessageDigest/MessageDigestCRC32.hpp \
    include/MessageDigest/MessageDigestMD5.hpp \
    include/MessageDigest/MessageDigestSHA1.hpp
