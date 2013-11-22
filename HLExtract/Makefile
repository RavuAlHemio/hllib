CC		=	gcc
CXX		=	g++
CFAMFLAGS	=	-Wall -O2 -g -fPIC -funroll-loops -fvisibility=hidden
CFLAGS		=
CXXFLAGS	=
PREFIX		=	/usr/local

all: hlextract

%.o: %.cpp
	$(CXX) -c $(CFAMFLAGS) $(CXXFLAGS) -o $@ $^

%.o: %.c
	$(CC) -c $(CFAMFLAGS) $(CFLAGS) -o $@ $^

clean:
	rm -f hlextract Main.o

install: hlextract
	install -g root -m 0755 -o root hlextract $(PREFIX)/bin

hlextract: Main.o ../HLLib/libhl.a
	$(CXX) $(LDFLAGS) -o $@ $^

.PHONY: all clean install
