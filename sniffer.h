// Copyright (c) 2012, Miriam Ruiz <miriam@debian.org>. All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 
//  1. Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
// 
//  2. Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in the
//     documentation and/or other materials provided with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER "AS IS", AND ANY EXPRESS
// OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN
// NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef SNIFFER_H_35C874BC_4DD1_11E2_AD2F_1BC708A5F99E_
#define SNIFFER_H_35C874BC_4DD1_11E2_AD2F_1BC708A5F99E_

struct pcap_pkthdr;

#include "ip_port_connection.h"
#include <map>
#include <iostream>

namespace filter {

class Sniffer {

public:
	Sniffer() {
	}

	virtual ~Sniffer() {
	}

	void loop(const char* devname);

	void printConnections(std::ostream& out);

protected:
	virtual void newPacket(const unsigned char * buffer, int size);

	typedef IpPortConnection<in_addr_t,u_int16_t> Connection;

	class Status {
	};

	typedef std::map<Connection,Status> ConnectionStatusMap;
	ConnectionStatusMap connections;
private:
	static void process_packet(unsigned char* arg, const struct pcap_pkthdr * header, const unsigned char * buffer);
};

}

#endif // SNIFFER_H_35C874BC_4DD1_11E2_AD2F_1BC708A5F99E_

