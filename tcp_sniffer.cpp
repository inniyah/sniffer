#include "tcp_sniffer.h"

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

static void print_ip_header(const struct iphdr & iph)
{
	struct sockaddr_in source;
	struct sockaddr_in dest;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph.saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph.daddr;

	printf("\n");
	printf("IP Header\n");
	printf("   |-IP Version        : %d\n",(unsigned int)iph.version);
	printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph.ihl,((unsigned int)(iph.ihl))*4);
	printf("   |-Type Of Service   : %d\n",(unsigned int)iph.tos);
	printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph.tot_len));
	printf("   |-Identification    : %d\n",ntohs(iph.id));
	//printf("   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr.ip_reserved_zero);
	//printf("   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr.ip_dont_fragment);
	//printf("   |-More Fragment Field   : %d\n",(unsigned int)iphdr.ip_more_fragment);
	printf("   |-TTL      : %d\n",(unsigned int)iph.ttl);
	printf("   |-Protocol : %d\n",(unsigned int)iph.protocol);
	printf("   |-Checksum : %d\n",ntohs(iph.check));
	printf("   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	printf("   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}

static void print_tcp_header(const struct tcphdr & tcph)
{
	printf("TCP Header\n");
	printf("   |-Source Port      : %u\n",ntohs(tcph.source));
	printf("   |-Destination Port : %u\n",ntohs(tcph.dest));
	printf("   |-Sequence Number    : %u\n",ntohl(tcph.seq));
	printf("   |-Acknowledge Number : %u\n",ntohl(tcph.ack_seq));
	printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph.doff,(unsigned int)tcph.doff*4);
	//printf("   |-CWR Flag : %d\n",(unsigned int)tcph.cwr);
	//printf("   |-ECN Flag : %d\n",(unsigned int)tcph.ece);
	printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph.urg);
	printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph.ack);
	printf("   |-Push Flag            : %d\n",(unsigned int)tcph.psh);
	printf("   |-Reset Flag           : %d\n",(unsigned int)tcph.rst);
	printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcph.syn);
	printf("   |-Finish Flag          : %d\n",(unsigned int)tcph.fin);
	printf("   |-Window         : %d\n",ntohs(tcph.window));
	printf("   |-Checksum       : %d\n",ntohs(tcph.check));
	printf("   |-Urgent Pointer : %d\n",tcph.urg_ptr);
}

static void print_raw_data (const void * pointer, int size)
{
	const u_char * data = (const u_char *) pointer;

	for(int i = 0 ; i < size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			printf("         ");
			for(int j = i-16 ; j < i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) {
					printf("%c",(unsigned char)data[j]); //if its a number or alphabet
				} else {
					printf("."); //otherwise print a dot
				}
			}
			printf("\n");
		} 

		if(i%16==0) {
			printf("   ");
		}

		printf(" %02X",(unsigned int)data[i]);

		if(i==size-1)  //print the last spaces
		{
			for(int j = 0 ; j < 15-i%16 ; j++) {
				printf("   "); //extra spaces
			}

			printf("         ");

			for(int j = i-i%16 ; j <= i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) {
					printf("%c",(unsigned char)data[j]);
				} else {
					printf(".");
				}
			}

			printf( "\n" );
		}
	}
}


void TcpSniffer::tcp_packet(const struct ethhdr & eth, const struct iphdr & iph, const struct tcphdr & tcph, const u_char * payload_buffer, int payload_size)
{
	TcpPacket packet(eth, iph, tcph, payload_buffer, payload_size);
	IpPortConnection conn_id(iph, tcph);

	//print_ip_header(iph);
	//print_tcp_header(tcph);
	conn_id.Print(); printf("\n");
	print_raw_data (payload_buffer, payload_size);

	TcpConnectionStatus & conn_status = connections[conn_id];
	(void)conn_status;

	printf("\n");
	printConnections();
	printf("\n");
}

void TcpSniffer::printConnections() {
	for (ConnectionStatusMap::const_iterator it = connections.begin(); it != connections.end(); it++) {
		const IpPortConnection & key = it->first;
		const TcpConnectionStatus & value = it->second;
		key.Print();
		printf(" -> State: %s\n", value.getStateName());
	}
}

void TcpConnectionStatus::tcp_packet(TcpSniffer & sniffer, TcpPacket & packet)
{
/*
	if (state) {
		if (true) {
			state->tcp_packet_sent(*this, sniffer, packet);
		} else {
			state->tcp_packet_rcvd(*this, sniffer, packet);
		}
	}
*/
}

TcpConnectionStatus::TcpConnectionStatus() : state(&state_closed) {
}

void TcpConnectionStatus::setState(State & new_state) {
	if (state)
		printf("FROM: %s ; TO: %s\n", state->state_name(), new_state.state_name());
	state = &new_state;
}

struct TcpConnectionStatus::StateClosed            TcpConnectionStatus::state_closed;
struct TcpConnectionStatus::StateSynSent           TcpConnectionStatus::state_syn_sent;
struct TcpConnectionStatus::StateSynSentSynAckRcvd TcpConnectionStatus::state_syn_sent_synack_rcvd;
struct TcpConnectionStatus::StateSynRcvd           TcpConnectionStatus::state_syn_rcvd;
struct TcpConnectionStatus::StateSynRcvdSynAckSent TcpConnectionStatus::state_syn_rcvd_synack_sent;
struct TcpConnectionStatus::StateEstablished       TcpConnectionStatus::state_established;
struct TcpConnectionStatus::StateClosing           TcpConnectionStatus::state_closing;

void TcpConnectionStatus::StateClosed::tcp_packet_sent(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet) {
	if (packet.tcph.syn)
		conn_status.setState(state_syn_sent);
}

void TcpConnectionStatus::StateClosed::tcp_packet_rcvd(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet) {
	if (packet.tcph.syn)
		conn_status.setState(state_syn_rcvd);
	else if (packet.tcph.rst)
		conn_status.setState(state_closed);
}

void TcpConnectionStatus::StateSynSent::tcp_packet_rcvd(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet) {
	if (packet.tcph.syn && packet.tcph.ack)
		conn_status.setState(state_syn_sent_synack_rcvd);
	else if (packet.tcph.rst)
		conn_status.setState(state_closed);
}

void TcpConnectionStatus::StateSynSentSynAckRcvd::tcp_packet_sent(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet) {
	if (packet.tcph.ack)
		conn_status.setState(state_established);
}

void TcpConnectionStatus::StateSynRcvd::tcp_packet_sent(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet) {
	if (packet.tcph.syn && packet.tcph.ack)
		conn_status.setState(state_syn_rcvd_synack_sent);
}

void TcpConnectionStatus::StateSynRcvd::tcp_packet_rcvd(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet) {
	if (packet.tcph.rst)
		conn_status.setState(state_closed);
}

void TcpConnectionStatus::StateSynRcvdSynAckSent::tcp_packet_rcvd(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet) {
	if (packet.tcph.ack)
		conn_status.setState(state_established);
	else if (packet.tcph.rst)
		conn_status.setState(state_closed);
}

void TcpConnectionStatus::StateEstablished::tcp_packet_sent(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet) {
	if (packet.tcph.fin)
		conn_status.setState(state_closing);
}

void TcpConnectionStatus::StateEstablished::tcp_packet_rcvd(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet) {
	if (packet.tcph.fin)
		conn_status.setState(state_closing);
}

void TcpConnectionStatus::StateClosing::tcp_packet_sent(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet) {
	if (packet.tcph.syn)
		conn_status.setState(state_syn_sent);
	else if (packet.tcph.ack)
		conn_status.setState(state_closed);
}

void TcpConnectionStatus::StateClosing::tcp_packet_rcvd(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet) {
	if (packet.tcph.syn)
		conn_status.setState(state_syn_rcvd);
	else if (packet.tcph.ack)
		conn_status.setState(state_closed);
}


