#ifndef TCP_SNIFFER_H_
#define TCP_SNIFFER_H_

#include "abstract_sniffer.h"
#include "ip_port_connection.h"

#include <stdio.h>
#include <netinet/in.h>

#include <map>

struct TcpPacket;
struct TcpSniffer;
struct TcpConnectionStatus;

struct TcpPacket {
	const struct ethhdr & eth;
	const struct iphdr & iph;
	const struct tcphdr & tcph;
	const unsigned char * data;
	const int data_size;

	TcpPacket(
		const struct ethhdr & p_eth,
		const struct iphdr & p_iph,
		const struct tcphdr & p_tcph,
		const unsigned char * payload_buffer,
		int payload_size
	) : eth(p_eth), iph(p_iph), tcph(p_tcph), data(payload_buffer), data_size(payload_size) {
	}

};

class TcpConnectionStatus {

public:
	TcpConnectionStatus();

	void tcp_packet(TcpSniffer & sniffer, TcpPacket & packet);

	inline const char * getStateName() const { return state ? state->state_name() : "NULL"; }

private:
	struct State {
		virtual const char * state_name() const = 0;
		virtual void tcp_packet_sent(TcpConnectionStatus& conn_status, TcpSniffer& sniffer, TcpPacket & packet) { }
		virtual void tcp_packet_rcvd(TcpConnectionStatus& conn_status, TcpSniffer& sniffer, TcpPacket & packet) { }
	} * state; // This variable will hold the current state of the TCP Transmission

	void setState(State & new_state);

	static struct StateClosed : public State {
		virtual const char * state_name() const { return "closed"; };
		virtual void tcp_packet_sent(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet);
		virtual void tcp_packet_rcvd(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet);
	} state_closed;

	static struct StateSynSent : public StateClosed {
		virtual const char * state_name() const { return "SYN sent"; };
		virtual void tcp_packet_rcvd(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet);
	} state_syn_sent;

	static struct StateSynSentSynAckRcvd : public StateClosed {
		virtual const char * state_name() const { return "SYN sent"; };
		virtual void tcp_packet_sent(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet);
	} state_syn_sent_synack_rcvd;

	static struct StateSynRcvd : public StateClosed {
		virtual const char * state_name() const { return "SYN received"; };
		virtual void tcp_packet_sent(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet);
		virtual void tcp_packet_rcvd(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet);
	} state_syn_rcvd;

	static struct StateSynRcvdSynAckSent : public StateClosed {
		virtual const char * state_name() const { return "SYN received"; };
		virtual void tcp_packet_rcvd(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet);
	} state_syn_rcvd_synack_sent;

	static struct StateEstablished : public State {
		virtual const char * state_name() const { return "established"; };
		virtual void tcp_packet_sent(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet);
		virtual void tcp_packet_rcvd(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet);
	} state_established;

	static struct StateClosing : public State {
		virtual const char * state_name() const { return "closing"; };
		virtual void tcp_packet_sent(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet);
		virtual void tcp_packet_rcvd(TcpConnectionStatus & conn_status, TcpSniffer& sniffer, TcpPacket & packet);
	} state_closing;

private:
};

class TcpSniffer : public AbstractSniffer {

public:

	TcpSniffer() {
	}

	~TcpSniffer() {
	}

	virtual void tcp_packet(const struct ethhdr & eth, const struct iphdr & iph, const struct tcphdr & tcph, const unsigned char * payload_buffer, int payload_size);

	void printConnections();

protected:
	void stats_updated() {
		fprintf(stderr, "ETH : %4u [ ARP : %4u   IP : %4u [ TCP : %4u   UDP : %4u   ICMP : %4u   IGMP : %4u ] ]\n",
			stat_eth, stat_arp, stat_ip, stat_tcp, stat_udp, stat_icmp, stat_igmp);
	}

	typedef std::map<IpPortConnection,TcpConnectionStatus> ConnectionStatusMap;
	ConnectionStatusMap connections;

};

#endif // TCP_SNIFFER_H_

