#ifndef PRINT_SNIFFER_H_
#define PRINT_SNIFFER_H_

#include "abstract_sniffer.h"

#include <stdio.h>

class PrintSniffer : public AbstractSniffer {

public:

	PrintSniffer(FILE *file) : logfile(file) {
	}

	virtual ~PrintSniffer() {
	}

	void print_ethernet_header(const struct ethhdr & eth);
	void print_ip_header(const struct iphdr & iph);
	void print_tcp_header(const struct tcphdr & tcph);
	void print_udp_header(const struct udphdr & udph);
	void print_icmp_header(const struct icmphdr & icmph);
	void print_arp_header(const struct arphdr & arph);

protected:

	virtual void tcp_packet(const struct ethhdr & eth, const struct iphdr & iph, const struct tcphdr & tcph, const unsigned char * payload_buffer, int payload_size);
	virtual void udp_packet(const struct ethhdr & eth, const struct iphdr & iph, const struct udphdr & udph, const unsigned char * payload_buffer, int payload_size);
	virtual void icmp_packet(const struct ethhdr & eth, const struct iphdr & iph, const struct icmphdr & icmph, const unsigned char * payload_buffer, int payload_size);
	virtual void arp_packet(const struct ethhdr & eth, const struct arphdr & arph,  const unsigned char * data_buffer, int data_size);

	void print_raw_data (const void * pointer, int size);

	FILE *logfile;
};

#endif // PRINT_SNIFFER_H_

