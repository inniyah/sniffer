#include "print_sniffer.h"

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


void PrintSniffer::print_ethernet_header(const struct ethhdr & eth)
{
	fprintf(logfile , "\n");
	fprintf(logfile , "Ethernet Header\n");
	fprintf(logfile , "   |-Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth.h_dest[0] , eth.h_dest[1] , eth.h_dest[2] , eth.h_dest[3] , eth.h_dest[4] , eth.h_dest[5] );
	fprintf(logfile , "   |-Source Address      : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth.h_source[0] , eth.h_source[1] , eth.h_source[2] , eth.h_source[3] , eth.h_source[4] , eth.h_source[5] );

	fprintf(logfile , "   |-Protocol            : 0x%04x",(unsigned short)htons(eth.h_proto));
	switch(ntohs(eth.h_proto)) {
		case ETH_P_IP:   fprintf(logfile , "  (IP, Internet Protocol)\n"); break;
		case ETH_P_ARP:  fprintf(logfile , "  (ARP, Address Resolution Protocol)\n"); break;
		case ETH_P_PAE:  fprintf(logfile , "  (PAE, Port Access Entity)\n"); break;
		default:         fprintf(logfile , "  (Unknown)\n"); break;
	}

	fprintf(logfile , "Ethernet Header\n");
	unsigned short ethhdrlen = sizeof(struct ethhdr);
	print_raw_data(&eth, ethhdrlen);
}

void PrintSniffer::print_ip_header(const struct iphdr & iph)
{
	struct sockaddr_in source;
	struct sockaddr_in dest;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph.saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph.daddr;

	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph.version);
	fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph.ihl,((unsigned int)(iph.ihl))*4);
	fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph.tos);
	fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph.tot_len));
	fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph.id));
	//fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr.ip_reserved_zero);
	//fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr.ip_dont_fragment);
	//fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr.ip_more_fragment);
	fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph.ttl);
	fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph.protocol);
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph.check));
	fprintf(logfile , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	fprintf(logfile , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );

	fprintf(logfile , "IP Header\n");
	unsigned short iphdrlen = iph.ihl*4;
	print_raw_data(&iph, iphdrlen);
}

void PrintSniffer::print_tcp_header(const struct tcphdr & tcph)
{
	fprintf(logfile , "TCP Header\n");
	fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph.source));
	fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph.dest));
	fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph.seq));
	fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph.ack_seq));
	fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph.doff,(unsigned int)tcph.doff*4);
	//fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph.cwr);
	//fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph.ece);
	fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph.urg);
	fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph.ack);
	fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph.psh);
	fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph.rst);
	fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph.syn);
	fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph.fin);
	fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph.window));
	fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph.check));
	fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph.urg_ptr);

	fprintf(logfile , "TCP Header\n");
	unsigned short tcphdrlen = tcph.doff*4;
	print_raw_data(&tcph, tcphdrlen);
}

void PrintSniffer::print_udp_header(const struct udphdr & udph)
{
	fprintf(logfile , "\nUDP Header\n");
	fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph.source));
	fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph.dest));
	fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph.len));
	fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph.check));

	fprintf(logfile , "UDP Header\n");
	unsigned short udphdrlen = sizeof(struct udphdr);
	print_raw_data(&udph, udphdrlen);
}

void PrintSniffer::print_icmp_header(const struct icmphdr & icmph)
{
	fprintf(logfile , "ICMP Header\n");
	fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph.type));

		switch ((unsigned int)(icmph.type)) {
		case ICMP_ECHOREPLY: 		fprintf(logfile , "  (Echo Reply)\n"); break;
		case ICMP_DEST_UNREACH:		fprintf(logfile , "  (Destination Unreachable)\n"); break;
		case ICMP_SOURCE_QUENCH:	fprintf(logfile , "  (Source Quench)\n"); break;
		case ICMP_REDIRECT:		fprintf(logfile , "  (Redirect: change route)\n"); break;
		case ICMP_ECHO:			fprintf(logfile , "  (Echo Request)\n"); break;
		case ICMP_TIME_EXCEEDED:	fprintf(logfile , "  (Time Exceeded)\n"); break;
		case ICMP_PARAMETERPROB:	fprintf(logfile , "  (Parameter Problem)\n"); break;
		case ICMP_TIMESTAMP:		fprintf(logfile , "  (Timestamp Request)\n"); break;
		case ICMP_TIMESTAMPREPLY:	fprintf(logfile , "  (Timestamp Reply)\n"); break;
		case ICMP_INFO_REQUEST:		fprintf(logfile , "  (Information Request)\n"); break;
		case ICMP_INFO_REPLY:		fprintf(logfile , "  (Information Reply)\n"); break;
		case ICMP_ADDRESS:		fprintf(logfile , "  (Address Mask Request)\n"); break;
		case ICMP_ADDRESSREPLY:		fprintf(logfile , "  (Address Mask Reply)\n"); break;
		default: fprintf(logfile , "  (Unknown)\n");
	}

	fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph.code));
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph.checksum));
	//fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph.id));
	//fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph.sequence));

	fprintf(logfile , "ICMP Header\n");
	unsigned short icmphdrlen = sizeof(struct icmphdr);
	print_raw_data(&icmph, icmphdrlen);
}

void PrintSniffer::print_arp_header(const struct arphdr & arph)
{
	fprintf(logfile , "ARP Header\n");
	fprintf(logfile , "   |-Hardware type    : %d" , (unsigned int)ntohs(arph.ar_hrd));
	switch(ntohs(arph.ar_hrd)) { // Defined in if_arp.h
		case ARPHRD_ETHER:    fprintf(logfile , "  (Ethernet 10/100Mbps)\n"); break;
		default:              fprintf(logfile , "  (Unknown)\n"); break;
	}

	fprintf(logfile , "   |-Protocol type    : %d" , (unsigned int)ntohs(arph.ar_pro));
	switch(ntohs(arph.ar_pro)) { // Defined in ethernet.h
		case ETHERTYPE_IP:    fprintf(logfile , "  (IPv4)\n"); break;
		case ETHERTYPE_IPV6:  fprintf(logfile , "  (IPv6)\n"); break;
		default:              fprintf(logfile , "  (Unknown)\n"); break;
	}

	fprintf(logfile , "   |-Operation        : %d" , ntohs(arph.ar_op));
	switch(ntohs(arph.ar_op)) { // Defined in if_arp.h
		case ARPOP_REQUEST:   fprintf(logfile , "  (ARP request)\n"); break;
		case ARPOP_REPLY:     fprintf(logfile , "  (ARP reply)\n"); break;
		case ARPOP_RREQUEST:  fprintf(logfile , "  (RARP request)\n"); break;
		case ARPOP_RREPLY:    fprintf(logfile , "  (RARP reply)\n"); break;
		case ARPOP_InREQUEST: fprintf(logfile , "  (InARP request)\n"); break;
		case ARPOP_InREPLY:   fprintf(logfile , "  (InARP reply)\n"); break;
		case ARPOP_NAK:       fprintf(logfile , "  (ARP NAK)\n"); break;
		default:              fprintf(logfile , "  (Unknown)\n"); break;
	}

	fprintf(logfile , "ARP Header\n");
	unsigned short arphdrhlen = arph.ar_hln; // Hardware Length
	unsigned short arphdrplen = arph.ar_pln; // Protocol Length
	unsigned short arphdrlen = sizeof(struct arphdr) + 2*arphdrhlen + 2*arphdrplen;
	print_raw_data(&arph, arphdrlen);
}

void PrintSniffer::tcp_packet(const struct ethhdr & eth, const struct iphdr & iph, const struct tcphdr & tcph, const u_char * payload_buffer, int payload_size)
{
	fprintf(logfile , "\n\n***********************TCP Packet*************************\n");	
	print_ethernet_header(eth);
	fprintf(logfile , "\n");
	print_ip_header(iph);
	fprintf(logfile , "\n");
	print_tcp_header(tcph);
	fprintf(logfile , "\n");

	fprintf(logfile , "Data Payload (%d bytes)\n", payload_size);
	print_raw_data(payload_buffer, payload_size);

	fprintf(logfile , "\n###########################################################");
}

void PrintSniffer::udp_packet(const struct ethhdr & eth, const struct iphdr & iph, const struct udphdr & udph, const u_char * payload_buffer, int payload_size)
{
	fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
	print_ethernet_header(eth);
	fprintf(logfile , "\n");
	print_ip_header(iph);
	fprintf(logfile , "\n");
	print_udp_header(udph);
	fprintf(logfile , "\n");

	fprintf(logfile , "Data Payload (%d bytes)\n", payload_size);
	print_raw_data(payload_buffer, payload_size);

	fprintf(logfile , "\n###########################################################");
}

void PrintSniffer::icmp_packet(const struct ethhdr & eth, const struct iphdr & iph, const struct icmphdr & icmph, const u_char * payload_buffer, int payload_size)
{
	fprintf(logfile , "\n\n***********************ICMP Packet*************************\n");	
	print_ethernet_header(eth);
	fprintf(logfile , "\n");
	print_ip_header(iph);
	fprintf(logfile , "\n");
	print_icmp_header(icmph);
	fprintf(logfile , "\n");

	fprintf(logfile , "Data Payload (%d bytes)\n", payload_size);
	print_raw_data(payload_buffer, payload_size);

	fprintf(logfile , "\n###########################################################");
}

struct arphdr_eth_ipv4
{
	unsigned char ar_sha[ETH_ALEN];	/* Sender hardware address.  */
	unsigned char ar_spa[4];	/* Sender IP address.  */
	unsigned char ar_tha[ETH_ALEN];	/* Target hardware address.  */
	unsigned char ar_tpa[4];	/* Target IP address.  */
};

void PrintSniffer::arp_packet(const struct ethhdr & eth, const struct arphdr & arph,  const u_char * data_buffer, int data_size)
{
	fprintf(logfile , "\n\n***********************ARP Packet*************************\n");
	print_ethernet_header(eth);
	fprintf(logfile , "\n");
	print_arp_header(arph);
	fprintf(logfile , "\n");

	if (ntohs(arph.ar_hrd) == ARPHRD_ETHER && ntohs(arph.ar_pro) == ETHERTYPE_IP) {
		const struct arphdr_eth_ipv4 * eth_ipv4 = (const struct arphdr_eth_ipv4 *)data_buffer;
		fprintf(logfile , "ARP Info\n");
		fprintf(logfile , "   |-Sender MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth_ipv4->ar_sha[0] , eth_ipv4->ar_sha[1] , eth_ipv4->ar_sha[2] , eth_ipv4->ar_sha[3] , eth_ipv4->ar_sha[4] , eth_ipv4->ar_sha[5] );
		fprintf(logfile , "   |-Sender IP: %u.%u.%u.%u\n", eth_ipv4->ar_spa[0] , eth_ipv4->ar_spa[1] , eth_ipv4->ar_spa[2] , eth_ipv4->ar_spa[3]); 
		fprintf(logfile , "   |-Target MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth_ipv4->ar_tha[0] , eth_ipv4->ar_tha[1] , eth_ipv4->ar_tha[2] , eth_ipv4->ar_tha[3] , eth_ipv4->ar_tha[4] , eth_ipv4->ar_tha[5] );
		fprintf(logfile , "   |-Target IP: %u.%u.%u.%u\n", eth_ipv4->ar_tpa[0] , eth_ipv4->ar_tpa[1] , eth_ipv4->ar_tpa[2] , eth_ipv4->ar_tpa[3]); 
	}
	fprintf(logfile , "ARP Info (%d bytes)\n", data_size);
	print_raw_data(data_buffer, data_size);

	fprintf(logfile , "\n###########################################################");
}

void PrintSniffer::print_raw_data (const void * pointer, int size)
{
	const u_char * data = (const u_char *) pointer;

	for(int i = 0 ; i < size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile , "         ");
			for(int j = i-16 ; j < i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) {
					fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
				} else {
					fprintf(logfile , "."); //otherwise print a dot
				}
			}
			fprintf(logfile , "\n");
		} 

		if(i%16==0) {
			fprintf(logfile , "   ");
		}

		fprintf(logfile , " %02X",(unsigned int)data[i]);

		if(i==size-1)  //print the last spaces
		{
			for(int j = 0 ; j < 15-i%16 ; j++) {
				fprintf(logfile , "   "); //extra spaces
			}

			fprintf(logfile , "         ");

			for(int j = i-i%16 ; j <= i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) {
					fprintf(logfile , "%c",(unsigned char)data[j]);
				} else {
					fprintf(logfile , ".");
				}
			}

			fprintf(logfile ,  "\n" );
		}
	}
}

