TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CXXFLAGS += -std=c++11

SOURCES += \
    src/main.cpp

HEADERS += \

unix: CONFIG += link_pkgconfig
unix: PKGCONFIG += cppunit