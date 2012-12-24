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

// Physical Layer: Ethernet's MAC Address

class PhysicalMacId : public PhysicalId {
public:
	PhysicalMacId(unsigned char * a) {
	for (int i = 0; i < ETH_ALEN ; i++)
		address[i] = a[i];
	}
	virtual const char * getIdTypeName() {
		return "MAC Address";
	}
	virtual bool isSameType (const PhysicalId &raw_other) const {
		return raw_other.isMacAddress();
	}
	virtual bool isMacAddress() const {
		return true;
	}
	virtual const unsigned char * getMacAddress() const {
		return address;
	}
protected:
	virtual bool less (const PhysicalId &other, bool equal);
	virtual bool equal (const PhysicalId &other);
private:
	MacAddress address;
};

bool PhysicalMacId::less (const PhysicalId &other, bool equal) {
	if (!other.isMacAddress()) return false;
	const unsigned char *other_address = other.getMacAddress();
	for (int i = 0; i < ETH_ALEN ; i++)
		if (address[i] < other_address[i])
			return true;
		else if (address[i] > other_address[i])
			return false;
	return equal;
}

bool PhysicalMacId::equal (const PhysicalId &other) {
	if (!other.isMacAddress()) return false;
	const unsigned char *other_address = other.getMacAddress();
	for (int i = ETH_ALEN-1; i >= 0 ; i--)
		if (address[i] != other_address[i])
			return false;
	return true;
}

// Network Layer: IP Address

class NetworkIpId : public NetworkId {
public:
	NetworkIpId(in_addr_t a) : addr(a) {
	}
	void print(std::ostream& where) const;
	virtual const char * getIdTypeName() {
		return "IP Address";
	}
	virtual bool isSameType (const NetworkId &other) {
		return other.isIpAddress();
	}
	virtual bool isIpAddress() const {
		return true;
	}
	virtual const in_addr_t getIpAddress() const {
		return addr;
	}
protected:
	virtual bool less (const NetworkId &other, bool equal) {
		if (!other.isIpAddress()) return false;
		in_addr_t other_addr = other.getIpAddress();
		return equal ? addr <= other_addr : addr < other_addr;
	}
	virtual bool equal (const NetworkId &other) {
		if (!other.isIpAddress()) return false;
		in_addr_t other_addr = other.getIpAddress();
		return addr == other_addr;
	}
private:
	in_addr_t addr;
};

void NetworkIpId::print(std::ostream& where) const {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_addr.s_addr = addr;
	where << inet_ntoa(sa.sin_addr);
}

// Abstract Header

void AbstractHeader::print(std::ostream& where) const {
	where << "Raw Data (" << getHeaderName() << ")" << std::endl;
	printRawData(where, data, data_len);
}

// Ethernet Header

AbstractHeader * EthernetHeader::createNextHeader() const {
	const struct ethhdr * eth = (const struct ethhdr *) data;
	unsigned short ethhdrlen = sizeof(struct ethhdr);
	const unsigned char * payload = data + ethhdrlen;
	unsigned int payload_size = data_len - ethhdrlen;

	switch (htons(eth->h_proto)) {
		case ETH_P_IP: // IP Protocol
			return new IpHeader(payload, payload_size, this);
		case ETH_P_ARP: // ARP Protocol
			return new ArpHeader(payload, payload_size, this);
		default:
			return new UnknownHeader(payload, payload_size, this);
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
			return new IcmpHeader(payload, payload_size, this);
			break;

		case 2: // IGMP Protocol
			return new IgmpHeader(payload, payload_size, this);
			break;

		case 6: // TCP Protocol
			return new TcpHeader(payload, payload_size, this);
			break;

		case 17: // UDP Protocol
			return new UdpHeader(payload, payload_size, this);
			break;

		default: // Other Protocols
			return new UnknownHeader(payload, payload_size, this);
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
	else return new PayloadData(payload, payload_size, this);
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
	else return new PayloadData(payload, payload_size, this);
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
	else return new PayloadData(payload, payload_size, this);
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

