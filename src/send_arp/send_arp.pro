TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += main.c \
	use_pcap.c \
	parsing.c \
    use_socket.c \
    common.c \
    build.c

HEADERS += common.h \
	use_pcap.h \
	parsing.h \
    use_socket.h \
    build.h
