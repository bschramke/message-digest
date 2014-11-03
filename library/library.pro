QT       -= core gui

TARGET = MessageDiggest
TEMPLATE = lib
VERSION = 0.0.1

DEFINES += LIBRARY_MESSAGE_DIGEST

QMAKE_CXXFLAGS += -std=c++11

INCLUDEPATH = $$PWD/include/

SOURCES += \
    src/MessageDigest.cpp

HEADERS += \
    include/MessageDigest/MessageDigest.hpp \
    include/MessageDigest/MessageDigestImpl.hpp
