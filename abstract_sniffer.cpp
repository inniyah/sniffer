#include "abstract_sniffer.h"

#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/if_arp.h>

AbstractSniffer::AbstractSniffer() {
	stat_eth = 0;
	stat_ip = 0;
	stat_tcp = 0;
	stat_udp = 0;
	stat_icmp = 0;
	stat_arp = 0;
	stat_igmp = 0;
}

AbstractSniffer::~AbstractSniffer() {
}

void AbstractSniffer::stats_updated() { }

void AbstractSniffer::loop(const char* devname) {
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

void AbstractSniffer::eth_packet(const u_char* buffer, int size) {
	struct ethhdr * eth = (struct ethhdr *)buffer;
	unsigned short ethhdrlen = sizeof(struct ethhdr);

	eth_packet(*eth, buffer + ethhdrlen, size - ethhdrlen);
}

void AbstractSniffer::tcp_packet(const u_char* buffer, int size) {
	struct ethhdr * eth = (struct ethhdr *)buffer;
	unsigned short ethhdrlen = sizeof(struct ethhdr);

	struct iphdr *iph = (struct iphdr *)( buffer + ethhdrlen );
	unsigned short iphdrlen = iph->ihl*4;

	struct tcphdr *tcph=(struct tcphdr*)( buffer + ethhdrlen + iphdrlen );
	unsigned short tcphdrlen = tcph->doff*4;

	int header_size = ethhdrlen + iphdrlen + tcphdrlen;

	tcp_packet(*eth, *iph, *tcph, buffer + header_size, size - header_size);
}

void AbstractSniffer::udp_packet(const u_char* buffer, int size) {
	struct ethhdr * eth = (struct ethhdr *)buffer;
	unsigned short ethhdrlen = sizeof(struct ethhdr);

	struct iphdr *iph = (struct iphdr *)( buffer +  ethhdrlen );
	unsigned short iphdrlen = iph->ihl*4;

	struct udphdr *udph = (struct udphdr*)( buffer + iphdrlen  + ethhdrlen );
	unsigned short udphdrlen = sizeof(struct udphdr);

	int header_size = ethhdrlen + iphdrlen + udphdrlen;

	udp_packet(*eth, *iph, *udph, buffer + header_size, size - header_size);
}

void AbstractSniffer::icmp_packet(const u_char* buffer, int size) {
	struct ethhdr * eth = (struct ethhdr *)buffer;
	unsigned short ethhdrlen = sizeof(struct ethhdr);

	struct iphdr *iph = (struct iphdr *)( buffer + ethhdrlen );
	unsigned short iphdrlen = iph->ihl*4;

	struct icmphdr *icmph = (struct icmphdr *)( buffer + iphdrlen  + ethhdrlen );
	unsigned short icmphdrlen = sizeof(struct icmphdr);

	int header_size = ethhdrlen + iphdrlen + icmphdrlen;

	icmp_packet(*eth, *iph, *icmph, buffer + header_size, size - header_size);
}

void AbstractSniffer::arp_packet(const u_char* buffer, int size) {
	struct ethhdr * eth = (struct ethhdr *)buffer;
	unsigned short ethhdrlen = sizeof(struct ethhdr);

	struct arphdr * arph = (struct arphdr *)( buffer + ethhdrlen );
	unsigned short arphdhrlen = sizeof(struct arphdr); // ARP header Lenght
	//unsigned short arphdhhlen = arph->ar_hln; // Hardware Length
	//unsigned short arphdrplen = arph->ar_pln; // Protocol Length

	int header_size = ethhdrlen + arphdhrlen;

	arp_packet(*eth, *arph, buffer + header_size, size - header_size);
}

void AbstractSniffer::process_packet(u_char* arg, const struct pcap_pkthdr * header, const u_char * buffer) {
	AbstractSniffer *sniffer = (AbstractSniffer *)arg;
	int size = header->len;

	struct ethhdr * eth = (struct ethhdr *)buffer;
	unsigned short ethhdrlen = sizeof(struct ethhdr);

	sniffer->stat_eth++;
	switch (htons(eth->h_proto)) {

		case ETH_P_IP: { // IP Protocol

				// Get the IP Header part of this packet , excluding the ethernet header
				struct iphdr *iph = (struct iphdr*)(buffer + ethhdrlen);

				sniffer->stat_ip++;
				switch (iph->protocol) //Check the Protocol and do accordingly...
				{
					case 1: // ICMP Protocol
						sniffer->stat_icmp++;
						sniffer->icmp_packet(buffer , size);
						break;

					case 2: // IGMP Protocol
						sniffer->stat_igmp++;
						break;

					case 6: // TCP Protocol
						sniffer->stat_tcp++;
						sniffer->tcp_packet(buffer , size);
						break;

					case 17: // UDP Protocol
						sniffer->stat_udp++;
						sniffer->udp_packet(buffer , size);
						break;

					default: // Other Protocols
						break;
				}

			} break; // ETH_P_IP

		case ETH_P_ARP: // ARP Protocol
			sniffer->stat_arp++;
			sniffer->arp_packet(buffer , size);
			break; // ETH_P_ARP

		default:
			sniffer->eth_packet(buffer , size);
	}

	sniffer->stats_updated();
}

