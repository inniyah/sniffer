# Copyright (c) 2012, Miriam Ruiz <miriam@debian.org>. All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
#  1. Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
# 
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER "AS IS", AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN
# NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

PROGRAM=sniffer

all: $(PROGRAM)

SOURCES = headers.cpp sniffer.cpp main.cpp
HEADERS = headers.h sniffer.h ip_port_connection.h

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

