#ifndef IP_PORT_CONNECTION_H_7C9BC74A_523B_11E2_A779_2F696D9D5D2F_
#define IP_PORT_CONNECTION_H_7C9BC74A_523B_11E2_A779_2F696D9D5D2F_

#include "headers.h"

#include <stdio.h>
#include <netinet/in.h>

namespace filter {

// IPv4 would be: IpPort<in_addr_t,u_int16_t>
template <typename NETID, typename PORT>
struct IpPort {
	NETID addr; // IP address
	PORT port; // Port

	IpPort() {
	}

	IpPort(const NETID &a, const PORT &p) : addr(a), port(p) {
	}

	void set(const NETID &a, const PORT &p) {
		addr = a; port = p;
	}

	bool operator< (const IpPort<NETID, PORT> &other) const {
		if ( port < other.port ) return true; // Check Port First
		if ( port > other.port ) return false;
		if ( addr < other.addr ) return true; // If Ports are equal, then Check IPs
		if ( addr > other.addr ) return false;
		return false;
	}

	inline bool operator>= (const IpPort<NETID, PORT> &other) const {
		return ! operator< (other);
	}

	bool operator<= (const IpPort<NETID, PORT> &other) const {
		if ( port < other.port ) return true; // Check Port First
		if ( port > other.port ) return false;
		if ( addr < other.addr ) return true; // If Ports are equal, then Check IPs
		if ( addr > other.addr ) return false;
		return true;
	}

	inline bool operator> (const IpPort<NETID, PORT> &other) const {
		return ! operator<= (other);
	}

	bool operator== (const IpPort<NETID, PORT> &other) const {
		if ( addr != other.addr ) return false;
		if ( port != other.port ) return false;
		return true;
	}

	inline bool operator!= (const IpPort<NETID, PORT> &other) const {
		return ! operator== (other);
	}

};

// IPv4 would be: IpPortConnection<in_addr_t,u_int16_t>
template <typename NETID, typename PORT>
struct IpPortConnection {
	IpPort<NETID, PORT> low;
	IpPort<NETID, PORT> high;

	IpPortConnection (const NETID &saddr, const PORT &sport, const NETID &daddr, const PORT &dport);

	bool less (const IpPortConnection<NETID, PORT> &other, bool equal) const {
		if ( low < other.low ) return true; // Check Lover ConnID First
		if ( low > other.low ) return false;
		if ( high < other.high ) return true; // If Low ConnIDs are equal, then check High ConnID
		if ( high > other.high ) return false;
		return equal;
	}

	bool equal (const IpPortConnection<NETID, PORT> &other) const {
		if ( low != other.low ) return false;
		if ( high != other.high ) return false;
		return true;
	}

	inline bool operator< (const IpPortConnection<NETID, PORT> &other) const {
		return less (other, false);
	}

	bool operator<= (const IpPortConnection<NETID, PORT> &other) const {
		return less (other, true);
	}

	bool operator> (const IpPortConnection<NETID, PORT> &other) const {
		return ! less (other, true);
	}

	bool operator>= (const IpPortConnection<NETID, PORT> &other) const {
		return ! less (other, false);
	}

	bool operator== (const IpPortConnection<NETID, PORT> &other) const {
		return equal (other);
	}

	bool operator!= (const IpPortConnection<NETID, PORT> &other) const {
		return ! equal (other);
	}

	bool lower_than(const NETID &saddr, const PORT &sport, const NETID &daddr, const PORT &dport) const;
};

template <typename NETID, typename PORT>
IpPortConnection<NETID,PORT>::IpPortConnection(const NETID &saddr, const PORT &sport, const NETID &daddr, const PORT &dport) {
	if (sport < dport) {        // Source port is lower
		low.set(saddr, sport);   high.set(daddr, dport);
	} else if (sport > dport) { // Dest port is higher
		high.set(saddr, sport);  low.set(daddr, dport);
	} else if (saddr < daddr) { // Source IP is lower
		low.set(saddr, sport);   high.set(daddr, dport);
	} else if (saddr > daddr) { // Dest IP is higher
		high.set(saddr, sport);  low.set(daddr, dport);
	} else { // They are equal
		high.set(saddr, sport);  low.set(daddr, dport);
	}
}

template <typename NETID, typename PORT>
bool IpPortConnection<NETID,PORT>::lower_than(const NETID &saddr, const PORT &sport, const NETID &daddr, const PORT &dport) const {
	IpPort<NETID,PORT> src(saddr, sport);
	IpPort<NETID,PORT> dst(daddr, dport);

	const IpPort<NETID,PORT> *other_low = &src; 
	const IpPort<NETID,PORT> *other_high = &dst; 
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

template <typename NETID, typename PORT>
inline std::ostream& operator<< (std::ostream& out, const IpPortConnection<NETID,PORT> & a) {
	out << a.low.addr << ":" << a.low.port << " <-> " << a.high.addr << ":" << a.high.port;
	return out;
}

} // namespace filter

#endif // IP_PORT_CONNECTION_H_7C9BC74A_523B_11E2_A779_2F696D9D5D2F_

