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
	const AbstractHeader *first_header = new EthernetHeader(buffer, size, NULL);
	const AbstractHeader *last_header = first_header;
	const AbstractHeader *header = last_header;
	do {
		last_header = header;
		//std::cout << *header << std::endl;
	} while (NULL != (header = header->createNextHeader()));

	// Print headers
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

	// Delete list of headers
	header = last_header;
	while (header) {
		const AbstractHeader *h = h;
		header = header->getPreviousHeader();
		delete h;
	}
}

void Sniffer::process_packet(u_char* arg, const struct pcap_pkthdr * header, const u_char * buffer) {
	Sniffer *sniffer = (Sniffer *)arg;
	int size = header->len;
	sniffer->newPacket(buffer, size);
}

void Sniffer::printConnections(std::ostream& out) {
	for (ConnectionStatusMap::const_iterator it = connections.begin(); it != connections.end(); it++) {
		const Connection & key = it->first; (void) key;
		const Status & value = it->second; (void) value;
		out << key << std::endl;
	}
}
