TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CXXFLAGS += -std=c++11

SOURCES += \
    src/main.cpp

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../library/release/ -lMessageDiggest
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../library/debug/ -lMessageDiggest
else:unix: LIBS += -L$$OUT_PWD/../library/ -lMessageDiggest

INCLUDEPATH += $$PWD/../library/include
DEPENDPATH += $$PWD/../library
