TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CXXFLAGS += -std=c++11

SOURCES += \
    src/main.cpp \
    src/MessageDigestCRC32Test.cpp \
    src/MessageDigestMD5Test.cpp \
    src/MessageDigestSHA1Test.cpp \
    src/MessageDigestSHA224Test.cpp \
    src/MessageDigestSHA256Test.cpp \
    src/MessageDigestSHA512Test.cpp \
    src/MessageDigestTest.cpp

HEADERS += \
    src/TestConstants.h \
    src/MessageDigestCRC32Test.hpp \
    src/MessageDigestMD5Test.hpp \
    src/MessageDigestSHA1Test.hpp \
    src/MessageDigestSHA224Test.hpp \
    src/MessageDigestSHA256Test.hpp \
    src/MessageDigestSHA512Test.hpp \
    src/MessageDigestTest.hpp

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../library/release/ -lMessageDiggest
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../library/debug/ -lMessageDiggest
else:unix: LIBS += -L$$OUT_PWD/../library/ -lMessageDiggest

INCLUDEPATH += $$PWD/../library/include
DEPENDPATH += $$PWD/../library

unix: CONFIG += link_pkgconfig
unix: PKGCONFIG += cppunit

