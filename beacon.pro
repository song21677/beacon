TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += \
    mac.cpp \
    main.cpp

HEADERS += \
    beacon.h \
    dot11.h \
    mac.h \
    radiotap.h
