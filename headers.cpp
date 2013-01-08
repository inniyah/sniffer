#include "headers.h"

#include <iostream>
#include <iomanip>

#include <stdarg.h>
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

// Helper Functions

static std::ostream& printWithFormat(std::ostream& out, const char * fmt, ...) {
	int size = 512;
	char * buffer = new char[size];

	va_list ap;

	while (1) {
		// Try to print in the allocated space
		va_start(ap, fmt);
		int n = vsnprintf(buffer, size, fmt, ap);
		va_end(ap);

		// If that worked, output the string
		if (n > -1 && n < size ) {
			out << buffer;
			delete[] buffer;
			return out;
		}

		// If not, try again with more space
		if (n > -1) // glibc 2.1
			size = n+1; // precisely what is needed, including  +1 for /0
		else  // glibc 2.0
			size *= 2;  // Twice the old size

		// Allocate a new buffer with the new size
		delete[] buffer;
		buffer = NULL;
		buffer = new char[size];
	}
}

static void printRawData (std::ostream& out, const void * pointer, int size)
{
	const u_char * data = (const u_char *) pointer;

	for(int i = 0 ; i < size ; i++) {
		if( i!=0 && i%16==0) { //if one line of hex printing is complete...
			printWithFormat(out , "         ");
			for(int j = i-16 ; j < i ; j++) {
				if(data[j]>=32 && data[j]<=128) {
					printWithFormat(out , "%c",(unsigned char)data[j]); //if its a number or alphabet
				} else {
					printWithFormat(out , "."); //otherwise print a dot
				}
			}
			out << std::endl;
		} 

		if(i%16==0) {
			printWithFormat(out , "   ");
		}

		printWithFormat(out , " %02X",(unsigned int)data[i]);

		if(i==size-1) { // Print the last spaces
			for(int j = 0 ; j < 15-i%16 ; j++) {
				printWithFormat(out , "   "); //extra spaces
			}

			printWithFormat(out , "         ");

			for(int j = i-i%16 ; j <= i ; j++) {
				if(data[j]>=32 && data[j]<=128) {
					printWithFormat(out , "%c",(unsigned char)data[j]);
				} else {
					printWithFormat(out , ".");
				}
			}

			out << std::endl;
		}
	}
}

// Basic Types

inline MacAddress::MacAddress() {
	memset(address, 0, sizeof(address));
}

inline MacAddress::MacAddress(const unsigned char * v) {
	memcpy(address, v, sizeof(address));
}

const unsigned char * MacAddress::operator=(const unsigned char * v) {
	memcpy(address, v, sizeof(address));
	return address;
}

bool MacAddress::less (const unsigned char * other, bool equal) const {
	for (int i = 0; i < ETH_ALEN ; i++)
		if (address[i] < other[i])
			return true;
		else if (address[i] > other[i])
			return false;
	return equal;
}

bool MacAddress::equal (const unsigned char * other) const {
	for (int i = ETH_ALEN-1; i >= 0 ; i--)
		if (address[i] != other[i])
			return false;
	return true;
}

std::ostream& operator<< (std::ostream& out, const MacAddress & v) {
	const unsigned char *address = v;
	printWithFormat(out, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		address[0], address[1], address[2], address[3], address[4], address[5] );
	return out;
}

inline std::ostream& operator<< (std::ostream& out, const IpAddress & v) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_addr.s_addr = in_addr_t(v);
	return out << inet_ntoa(sa.sin_addr);
}

inline std::ostream& operator<< (std::ostream& out, const PortNumber & v) {
	return out << u_int16_t(v);
}

// Abstract Header

void AbstractHeader::print(std::ostream& where) const {
	where << "Raw Data (" << getHeaderName() << ")" << std::endl;
	printRawData(where, data, data_len);
}

unsigned int AbstractHeader::next_id = 0;

template<typename DERIVED>
unsigned int HeaderAux<DERIVED>::id = 0;

// Ethernet Header

AbstractHeader * EthernetHeader::createNextHeader() const {
	const struct ethhdr * eth = (const struct ethhdr *) data;
	unsigned short ethhdrlen = sizeof(struct ethhdr);
	const unsigned char * payload = data + ethhdrlen;
	unsigned int payload_size = data_len - ethhdrlen;

	switch (htons(eth->h_proto)) {
		case ETH_P_IP: // IP Protocol
			return IpHeader::createHeader(payload, payload_size, this);
		case ETH_P_ARP: // ARP Protocol
			return ArpHeader::createHeader(payload, payload_size, this);
		default:
			return UnknownHeader::createHeader(payload, payload_size, this);
	}
}

void EthernetHeader::print(std::ostream& where) const {
	const struct ethhdr * eth = (const struct ethhdr *) data;
	unsigned short ethhdrlen = sizeof(struct ethhdr);

	const MacAddress &src_mac = eth->h_source; // Source Mac Address
	const MacAddress &tgt_mac = eth->h_dest;   // Target Mac Address
	
	where << "Ethernet Header" << std::endl;
	printWithFormat(where, "   |-Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		tgt_mac[0], tgt_mac[1], tgt_mac[2], tgt_mac[3], tgt_mac[4], tgt_mac[5] );
	where << std::endl;
	printWithFormat(where, "   |-Source Address      : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5] );
	where << std::endl;
	where << "   |-Protocol            : " << htons(eth->h_proto);
	switch(ntohs(eth->h_proto)) {
		case ETH_P_IP:   where << "  (IP, Internet Protocol)" <<  std::endl; break;
		case ETH_P_ARP:  where << "  (ARP, Address Resolution Protocol)" <<  std::endl; break;
		case ETH_P_PAE:  where << "  (PAE, Port Access Entity)" <<  std::endl; break;
		default:         where << "  (Unknown)" <<  std::endl;
	}
	where << "Ethernet Header (Raw Data)" << std::endl;
	printRawData(where, &eth, ethhdrlen);
}

// IP Header

AbstractHeader * IpHeader::createNextHeader() const {
	const struct iphdr *iph = (const struct iphdr*) data;
	unsigned short iphdrlen = iph->ihl*4;
	const unsigned char * payload = data + iphdrlen;
	unsigned int payload_size = data_len - iphdrlen;

	switch (iph->protocol) {
		case 1: // ICMP Protocol
			return IcmpHeader::createHeader(payload, payload_size, this);
			break;

		case 2: // IGMP Protocol
			return IgmpHeader::createHeader(payload, payload_size, this);
			break;

		case 6: // TCP Protocol
			return TcpHeader::createHeader(payload, payload_size, this);
			break;

		case 17: // UDP Protocol
			return UdpHeader::createHeader(payload, payload_size, this);
			break;

		default: // Other Protocols
			return UnknownHeader::createHeader(payload, payload_size, this);
			break;
	}
}

void IpHeader::print(std::ostream& where) const {
	const struct iphdr *iph = (const struct iphdr*) data;
	unsigned short iphdrlen = iph->ihl*4;

	struct sockaddr_in src;
	memset(&src, 0, sizeof(struct sockaddr_in));
	src.sin_addr.s_addr = iph->saddr;

	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(struct sockaddr_in));
	dst.sin_addr.s_addr = iph->daddr;

	where << "IP Header" << std::endl;
	where << "   |-IP Version        : " << (unsigned int)iph->version << std::endl;
	where << "   |-IP Header Length  : " << (unsigned int)iph->ihl << " DWORDS or "
		<< (unsigned int)((iph->ihl)*4) << " Bytes" << std::endl;
	where << "   |-Type Of Service   : " << (unsigned int)iph->tos << std::endl;
	where << "   |-IP Total Length   : " << ntohs(iph->tot_len) << "  Bytes(Size of Packet" << std::endl;
	where << "   |-Identification    : " << ntohs(iph->id) << std::endl;
	//where << "   |-Reserved ZERO Field   : " <<(unsigned int)iphdr->ip_reserved_zero << std::endl;
	//where << "   |-Dont Fragment Field   : " <<(unsigned int)iphdr->ip_dont_fragment << std::endl;
	//where << "   |-More Fragment Field   : " <<(unsigned int)iphdr->ip_more_fragment << std::endl;
	where << "   |-TTL      : " << (unsigned int)iph->ttl << std::endl;
	where << "   |-Protocol : " << (unsigned int)iph->protocol << std::endl;
	where << "   |-Checksum : " << ntohs(iph->check) << std::endl;
	where << "   |-Source IP        : " << inet_ntoa(src.sin_addr) << std::endl;
	where << "   |-Destination IP   : " << inet_ntoa(dst.sin_addr) << std::endl;

	where << "IP Header (Raw Data)" << std::endl;
	printRawData(where, &iph, iphdrlen);
}

// TCP Header

AbstractHeader * TcpHeader::createNextHeader() const {
	const struct tcphdr *tcph=(const struct tcphdr*) data;
	unsigned short tcphdrlen = tcph->doff*4;
	const unsigned char * payload = data + tcphdrlen;
	unsigned int payload_size = data_len - tcphdrlen;
	if (!payload_size) return NULL;
	else return PayloadData::createHeader(payload, payload_size, this);
}

void TcpHeader::print(std::ostream& where) const {
	const struct tcphdr *tcph=(const struct tcphdr*) data;
	unsigned short tcphdrlen = tcph->doff*4;

	where << "TCP Header" << std::endl;
	where << "   |-Source Port      : " << ntohs(tcph->source) << std::endl;
	where << "   |-Destination Port : " << ntohs(tcph->dest) << std::endl;
	where << "   |-Sequence Number    : " << ntohl(tcph->seq) << std::endl;
	where << "   |-Acknowledge Number : " << ntohl(tcph->ack_seq) << std::endl;
	where << "   |-Header Length      : " << (unsigned int)tcph->doff << " DWORDS or "
		<< (unsigned int)(tcph->doff*4) << " BYTES" << std::endl;
	//where << "   |-CWR Flag : " << (unsigned int)tcph->cwr << std::endl;
	//where << "   |-ECN Flag : ",<< (unsigned int)tcph->ece << std::endl;
	where << "   |-Urgent Flag          : " << (unsigned int)tcph->urg << std::endl;
	where << "   |-Acknowledgement Flag : " << (unsigned int)tcph->ack << std::endl;
	where << "   |-Push Flag            : " << (unsigned int)tcph->psh << std::endl;
	where << "   |-Reset Flag           : " << (unsigned int)tcph->rst << std::endl;
	where << "   |-Synchronise Flag     : " << (unsigned int)tcph->syn << std::endl;
	where << "   |-Finish Flag          : " << (unsigned int)tcph->fin << std::endl;
	where << "   |-Window         : " << ntohs(tcph->window) << std::endl;
	where << "   |-Checksum       : " << ntohs(tcph->check) << std::endl;
	where << "   |-Urgent Pointer : " << tcph->urg_ptr << std::endl;

	where << "TCP Header (Raw Data)" << std::endl;
	printRawData(where, &tcph, tcphdrlen);
}

// UDP Header

AbstractHeader * UdpHeader::createNextHeader() const {
	//const struct udphdr *udph = (const struct udphdr*) data;
	unsigned short udphdrlen = sizeof(struct udphdr);
	const unsigned char * payload = data + udphdrlen;
	unsigned int payload_size = data_len - udphdrlen;
	if (!payload_size) return NULL;
	else return PayloadData::createHeader(payload, payload_size, this);
}

void UdpHeader::print(std::ostream& where) const {
	const struct udphdr *udph = (const struct udphdr*) data;
	unsigned short udphdrlen = sizeof(struct udphdr);

	where << "UDP Header" << std::endl;
	where << "   |-Source Port      : " << ntohs(udph->source) << std::endl;
	where << "   |-Destination Port : " << ntohs(udph->dest) << std::endl;
	where << "   |-UDP Length       : " << ntohs(udph->len) << std::endl;
	where << "   |-UDP Checksum     : " << ntohs(udph->check) << std::endl;

	where << "UDP Header (Raw Data)" << std::endl;
	printRawData(where, &udph, udphdrlen);
}

// ICMP Header

AbstractHeader * IcmpHeader::createNextHeader() const {
	//const struct icmphdr *icmph = (const struct icmphdr *) data;
	unsigned short icmphdrlen = sizeof(struct icmphdr);
	const unsigned char * payload = data + icmphdrlen;
	unsigned int payload_size = data_len - icmphdrlen;
	if (!payload_size) return NULL;
	else return PayloadData::createHeader(payload, payload_size, this);
}

void IcmpHeader::print(std::ostream& where) const {
	const struct icmphdr *icmph = (const struct icmphdr *) data;
	unsigned short icmphdrlen = sizeof(struct icmphdr);

	where <<  "ICMP Header" << std::endl;
	where <<  "   |-Type : " << (unsigned int)icmph->type << std::endl;

	switch ((unsigned int)icmph->type) {
		case ICMP_ECHOREPLY: 		where << "  (Echo Reply)" << std::endl; break;
		case ICMP_DEST_UNREACH:		where << "  (Destination Unreachable)" << std::endl; break;
		case ICMP_SOURCE_QUENCH:	where << "  (Source Quench)" << std::endl; break;
		case ICMP_REDIRECT:		where << "  (Redirect: change route)" << std::endl; break;
		case ICMP_ECHO:			where << "  (Echo Request)" << std::endl; break;
		case ICMP_TIME_EXCEEDED:	where << "  (Time Exceeded)" << std::endl; break;
		case ICMP_PARAMETERPROB:	where << "  (Parameter Problem)" << std::endl; break;
		case ICMP_TIMESTAMP:		where << "  (Timestamp Request)" << std::endl; break;
		case ICMP_TIMESTAMPREPLY:	where << "  (Timestamp Reply)" << std::endl; break;
		case ICMP_INFO_REQUEST:		where << "  (Information Request)" << std::endl; break;
		case ICMP_INFO_REPLY:		where << "  (Information Reply)" << std::endl; break;
		case ICMP_ADDRESS:		where << "  (Address Mask Request)" << std::endl; break;
		case ICMP_ADDRESSREPLY:		where << "  (Address Mask Reply)" << std::endl; break;
		default:			where << "  (Unknown)" << std::endl;
	}

	where <<  "   |-Code : " << (unsigned int)icmph->code << std::endl;
	where <<  "   |-Checksum : " << ntohs(icmph->checksum) << std::endl;
	//where <<  "   |-ID       : " << ntohs(icmph->id) << std::endl;
	//where <<  "   |-Sequence : " << ntohs(icmph->sequence) << std::endl;

	where << "ICMP Header (Raw Data)" << std::endl;
	printRawData(where, &icmph, icmphdrlen);
}

void ArpHeader::print(std::ostream& where) const {
	const struct arphdr * arph = (const struct arphdr *) data;
	//unsigned short arphdrlen = sizeof(struct arphdr); // ARP header Lenght
	//unsigned short arphdrhwlen = arph->ar_hln; // Hardware Length
	//unsigned short arphdrprlen = arph->ar_pln; // Protocol Length

	where <<  "ARP Header" << std::endl;
	where <<  "   |-Hardware type    : " << ntohs(arph->ar_hrd);
	switch(ntohs(arph->ar_hrd)) { // Defined in if_arp.h
		case ARPHRD_ETHER:    where <<  "  (Ethernet 10/100Mbps)" << std::endl; break;
		default:              where <<  "  (Unknown)" << std::endl;
	}

	where <<  "   |-Protocol type    : " << ntohs(arph->ar_pro);
	switch(ntohs(arph->ar_pro)) { // Defined in ethernet.h
		case ETHERTYPE_IP:    where <<  "  (IPv4)" << std::endl; break;
		case ETHERTYPE_IPV6:  where <<  "  (IPv6)" << std::endl; break;
		default:              where <<  "  (Unknown)" << std::endl;
	}

	where <<  "   |-Operation        : " << ntohs(arph->ar_op);
	switch(ntohs(arph->ar_op)) { // Defined in if_arp.h
		case ARPOP_REQUEST:   where <<  "  (ARP request)" << std::endl; break;
		case ARPOP_REPLY:     where <<  "  (ARP reply)" << std::endl; break;
		case ARPOP_RREQUEST:  where <<  "  (RARP request)" << std::endl; break;
		case ARPOP_RREPLY:    where <<  "  (RARP reply)" << std::endl; break;
		case ARPOP_InREQUEST: where <<  "  (InARP request)" << std::endl; break;
		case ARPOP_InREPLY:   where <<  "  (InARP reply)" << std::endl; break;
		case ARPOP_NAK:       where <<  "  (ARP NAK)" << std::endl; break;
		default:              where <<  "  (Unknown)" << std::endl;
	}
}

AbstractHeader * ArpHeader::createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header) {
	const struct arphdr * arph = (const struct arphdr *) buffer;
	if (ntohs(arph->ar_hrd) == ARPHRD_ETHER && ntohs(arph->ar_pro) == ETHERTYPE_IP)
		return new ArpEthIpHeader(buffer, len, prev_header);
	return new ArpHeader(buffer, len, prev_header);
}

void ArpEthIpHeader::print(std::ostream& where) const {
	ArpHeader::print(where);
	//const struct arphdr * arph = (const struct arphdr *) data;
	unsigned short arphdrlen = sizeof(struct arphdr); // ARP header Lenght
	const struct arphdr_eth_ipv4 * eth_ipv4 = (const struct arphdr_eth_ipv4 *)(data + arphdrlen);

	printWithFormat(where, "   |-Sender MAC       : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		eth_ipv4->ar_sha[0], eth_ipv4->ar_sha[1], eth_ipv4->ar_sha[2],
		eth_ipv4->ar_sha[3], eth_ipv4->ar_sha[4], eth_ipv4->ar_sha[5] );
	where << std::endl;

	printWithFormat(where, "   |-Sender IP        : %u.%u.%u.%u",
		eth_ipv4->ar_spa[0], eth_ipv4->ar_spa[1], eth_ipv4->ar_spa[2], eth_ipv4->ar_spa[3]);
	where << std::endl;

	printWithFormat(where, "   |-Target MAC       : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
		eth_ipv4->ar_tha[0], eth_ipv4->ar_tha[1], eth_ipv4->ar_tha[2],
		eth_ipv4->ar_tha[3], eth_ipv4->ar_tha[4], eth_ipv4->ar_tha[5] );
	where << std::endl;

	printWithFormat(where, "   |-Sender IP        : %u.%u.%u.%u",
		eth_ipv4->ar_tpa[0], eth_ipv4->ar_tpa[1], eth_ipv4->ar_tpa[2], eth_ipv4->ar_tpa[3]);
	where << std::endl;
}

