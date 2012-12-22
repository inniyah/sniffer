#include "ip_port_connection.h"

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

IpPortConnection::IpPortConnection (const struct iphdr & iph, const struct tcphdr & tcph) {
	const in_addr_t & saddr = iph.saddr; // Source IP address
	const u_int16_t sport = ntohs(tcph.source); // Source Port
	const in_addr_t & daddr = iph.daddr; // Target IP address
	const u_int16_t dport = ntohs(tcph.dest); // Target Port

	if (sport < dport) { // Source port is lower
		low.set(saddr, sport);   high.set(daddr, dport);
	} else if (sport > dport) { // Dest port is higher
		high.set(saddr, sport);  low.set(daddr, dport);
	} else if (saddr < daddr) { // Source IP is lower
		low.set(saddr, sport);   high.set(daddr, dport);
	} else if (saddr > daddr) { // Dest IP is higher
		high.set(saddr, sport); low.set(daddr, dport);
	} else { // They are equal
		high.set(saddr, sport);  low.set(daddr, dport);
	}
}

bool IpPortConnection::lower_than(const struct iphdr & iph, const struct tcphdr & tcph) const {
	IpPort src(iph.saddr, ntohs(tcph.source));
	IpPort dst(iph.daddr, ntohs(tcph.dest));

	const IpPort *other_low = &src; 
	const IpPort *other_high = &dst; 
	if (*other_low > *other_high) {
		other_low  = &dst;
		other_high = &src;
	}

	if ( low  < *other_low ) return true;
	if ( low  > *other_low ) return false;
	if ( high < *other_high ) return true;
	if ( high > *other_high ) return false;
	return false;
}

void IpPortConnection::Print() const {
	struct sockaddr_in sa_lo;
	struct sockaddr_in sa_hi;
	memset(&sa_lo, 0, sizeof(struct sockaddr_in));
	sa_lo.sin_addr.s_addr = low.addr;
	memset(&sa_hi, 0, sizeof(struct sockaddr_in));
	sa_hi.sin_addr.s_addr = high.addr;

	// Hatta do it in two lines, 'cos inet_ntoa uses a global buffer that gets overwritten otherwise
	printf("%s:%u <-> ", inet_ntoa(sa_lo.sin_addr), low.port);
	printf("%s:%u", inet_ntoa(sa_hi.sin_addr), high.port);
}

