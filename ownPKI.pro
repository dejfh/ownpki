#-------------------------------------------------
#
# Project created by QtCreator 2013-09-16T20:07:32
#
#-------------------------------------------------

#QT       -= gui

TARGET    = ownPKI
CONFIG   += console
CONFIG   -= qt

TEMPLATE = app

INCLUDEPATH += C:/OpenSSL-Win64/include

SOURCES += \
    passwd.cpp \
    x509builder.cpp \
    rsakeybuilder.cpp \
    ownpki.cpp

    
HEADERS += \
    asnref.h \
    extensions.h \
    x509builder.h \
    rsakeybuilder.h \
    ownpki.h

win32 {
LIBS += -LC:/OpenSSL-Win64/lib/VC/static

LIBS += \
    -llibeay32MDd \
    -luser32 \
    -lgdi32 \
    -ladvapi32
}
else {
LIBS += \
    -lcrypto
}
