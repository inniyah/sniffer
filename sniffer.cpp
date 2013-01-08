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
	const AbstractHeader *first_header = new EthernetHeader(buffer, size, NULL);

	const AbstractHeader *last_header = first_header;
	do {
		std::cout << *last_header << std::endl;
	} while (NULL != (last_header = last_header->createNextHeader()));

	const AbstractHeader *header = last_header;
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

