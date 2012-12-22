#ifndef IP_PORT_CONNECTION_H_
#define IP_PORT_CONNECTION_H_

#include <stdio.h>
#include <netinet/in.h>

struct IpPort {
	in_addr_t addr; // IP address
	u_int16_t port; // Port

	IpPort() : addr(0), port(0) {
	}

	IpPort(in_addr_t a, u_int16_t p) : addr(a), port(p) {
	}

	void set(const in_addr_t a, const u_int16_t p) {
		addr = a; port = p;
	}

	bool operator< (const IpPort &other) const {
		if ( port < other.port ) return true; // Check Port First
		if ( port > other.port ) return false;
		if ( addr < other.addr ) return true; // If Ports are equal, then Check IPs
		if ( addr > other.addr ) return false;
		return false;
	}

	inline bool operator>= (const IpPort &other) const {
		return ! operator< (other);
	}

	bool operator<= (const IpPort &other) const {
		if ( port < other.port ) return true; // Check Port First
		if ( port > other.port ) return false;
		if ( addr < other.addr ) return true; // If Ports are equal, then Check IPs
		if ( addr > other.addr ) return false;
		return true;
	}

	inline bool operator> (const IpPort &other) const {
		return ! operator<= (other);
	}

	bool operator== (const IpPort &other) const {
		if ( addr != other.addr ) return false;
		if ( port != other.port ) return false;
		return true;
	}

	inline bool operator!= (const IpPort &other) const {
		return ! operator== (other);
	}

};


struct IpPortConnection {
	IpPort low;
	IpPort high;

	IpPortConnection (const struct iphdr & iph, const struct tcphdr & tcph);

	bool less (const IpPortConnection &other, bool equal) const {
		if ( low < other.low ) return true; // Check Lover ConnID First
		if ( low > other.low ) return false;
		if ( high < other.high ) return true; // If Low ConnIDs are equal, then check High ConnID
		if ( high > other.high ) return false;
		return equal;
	}

	bool equal (const IpPortConnection &other) const {
		if ( low != other.low ) return false;
		if ( high != other.high ) return false;
		return true;
	}

	inline bool operator< (const IpPortConnection &other) const {
		return less (other, false);
	}

	bool operator<= (const IpPortConnection &other) const {
		return less (other, true);
	}

	bool operator> (const IpPortConnection &other) const {
		return ! less (other, true);
	}

	bool operator>= (const IpPortConnection &other) const {
		return ! less (other, false);
	}

	bool operator== (const IpPortConnection &other) const {
		return equal (other);
	}

	bool operator!= (const IpPortConnection &other) const {
		return ! equal (other);
	}

	bool lower_than(const struct iphdr & iph, const struct tcphdr & tcph) const;

	void Print() const;
};

#endif // IP_PORT_CONNECTION_H_

