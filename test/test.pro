TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CXXFLAGS += -std=c++11

SOURCES += \
    src/main.cpp \
    src/MessageDigestMD5Test.cpp \
    src/MessageDigestSHA1Test.cpp

HEADERS += \
    src/TestConstants.h \
    src/MessageDigestMD5Test.hpp \
    src/MessageDigestSHA1Test.hpp

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../library/release/ -lMessageDiggest
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../library/debug/ -lMessageDiggest
else:unix: LIBS += -L$$OUT_PWD/../library/ -lMessageDiggest

INCLUDEPATH += $$PWD/../library/include
DEPENDPATH += $$PWD/../library

unix: CONFIG += link_pkgconfig
unix: PKGCONFIG += cppunit

