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

#include "sniffer.h"
#include "headers.h"
#include "ip_port_connection.h"

#include <pcap.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/if_arp.h>

using namespace filter;

void Sniffer::loop(const char* devname) {
	printf("Opening device %s for sniffing ... " , devname);

	pcap_t* handle; // Handle of the device that shall be sniffed
	char errbuf[100];

	// Open device for sniffing
	handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);

	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
		exit(1);
	}

	printf("Sniffing...\n");

	// Put the device in sniff loop
	pcap_loop(handle, -1, process_packet, (u_char*)this);
}

void Sniffer::newPacket(const unsigned char * buffer, int size) {
	// Create list of headers from buffer
	EthernetHeader first_header(buffer, size);

	// Find the last header
	AbstractHeader *last_header = &first_header;
	AbstractHeader *header = last_header;
	do {
		last_header = header;
		//std::cout << *header << std::endl;
	} while (NULL != (header = header->getNextHeader()));

	// Print headers in reverse order
	const AbstractHeader *payload_data = NULL; (void)payload_data;
	const AbstractHeader *transport_header = NULL; (void)transport_header;
	const AbstractHeader *network_layer = NULL; (void)network_layer;
	for (const AbstractHeader *h = last_header; h != NULL; h = h->getPreviousHeader() ) {
		if (!transport_header && (h->getLayers() | PAYLOAD_DATA) != 0)
				payload_data = h;

		if (!transport_header) {
			if ((h->getLayers() | TRANSPORT_LAYER) != 0)
				transport_header = h;
		} else if (!network_layer) {
			if ((h->getLayers() | NETWORK_LAYER) != 0)
				network_layer = h;
		}

		std::cout << "<< " << *h << std::endl;
	}
}

void Sniffer::process_packet(u_char* arg, const struct pcap_pkthdr * header, const u_char * buffer) {
	Sniffer *sniffer = (Sniffer *)arg;
	int size = header->len;
	sniffer->newPacket(buffer, size);
	std::cout << "     ----------" << std::endl;
}

void Sniffer::printConnections(std::ostream& out) {
	for (ConnectionStatusMap::const_iterator it = connections.begin(); it != connections.end(); it++) {
		const Connection & key = it->first; (void) key;
		const Status & value = it->second; (void) value;
		out << key << std::endl;
	}
}
