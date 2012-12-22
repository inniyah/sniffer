PROGRAM=sniffer

all: $(PROGRAM)

SOURCES = abstract_sniffer.cpp print_sniffer.cpp main.cpp
HEADERS = abstract_sniffer.h print_sniffer.h

OBJS = $(SOURCES:.cpp=.o)

#PKG_CONFIG=
#PKG_CONFIG_CFLAGS=`pkg-config --cflags $(PKG_CONFIG)`
#PKG_CONFIG_LIBS=`pkg-config --libs $(PKG_CONFIG)`

EXTRA_CFLAGS=-I.
#EXTRA_CFLAGS=-I. $(PKG_CONFIG_CFLAGS)
CFLAGS= -O2 -g -Wall

LDFLAGS= -Wl,-z,defs -Wl,--as-needed -Wl,--no-undefined
EXTRA_LDFLAGS=
LIBS=-lpcap
#LIBS=$(PKG_CONFIG_LIBS)

$(PROGRAM): $(OBJS)
	g++ $(LDFLAGS) $(EXTRA_LDFLAGS) $+ -o $@ $(LIBS)

%.o: %.cpp $(HEADERS)
	g++ -o $@ -c $< $(CFLAGS) $(EXTRA_CFLAGS)

%.o: %.c $(HEADERS)
	gcc -o $@ -c $< $(CFLAGS) $(EXTRA_CFLAGS)

clean:
	rm -f $(OBJS)
	rm -f $(PROGRAM)
	rm -f *.o *.a *~

