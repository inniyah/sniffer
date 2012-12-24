#ifndef HEADERS_H_25E85D1E_4C87_11E2_BB32_7BDCB76BDF0B_
#define HEADERS_H_25E85D1E_4C87_11E2_BB32_7BDCB76BDF0B_

#include <iostream>

#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/if_arp.h>

namespace filter {

	typedef unsigned char MacAddress[ETH_ALEN];
	typedef in_addr_t IpAddress;
	typedef u_int16_t PortNumber;

class AbstractId {
public:
	virtual void print(std::ostream& where) const = 0;
	virtual const char * getIdTypeName() = 0;

	inline bool operator< (const AbstractId &other) const {
		return less (other, false);
	}

	inline bool operator<= (const AbstractId &other) const {
		return less (other, true);
	}

	inline bool operator> (const AbstractId &other) const {
		return ! less (other, true);
	}

	inline bool operator>= (const AbstractId &other) const {
		return ! less (other, false);
	}

	inline bool operator== (const AbstractId &other) const {
		return equal (other);
	}

	inline bool operator!= (const AbstractId &other) const {
		return ! equal (other);
	}
	virtual bool isSameType (const AbstractId &other) const {
		return false;
	}

protected:
	virtual bool less (const AbstractId &other, bool equal) const = 0;
	virtual bool equal (const AbstractId &other) const = 0;
};

class PhysicalId : public AbstractId {
public:
	virtual bool isMacAddress() const { return false; }
	virtual const unsigned char * getMacAddress() const { return NULL; }
};

class NetworkId : public AbstractId {
public:
	virtual bool isIpAddress() const { return false; }
	virtual const in_addr_t getIpAddress() const { return 0; }
};

class AbstractHeader {
public:
	AbstractHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: data((unsigned char *)buffer), data_len(len), prev(prev_header) { }
	virtual ~AbstractHeader() { }
	virtual const char * getHeaderName() const = 0;
	virtual AbstractHeader * createNextHeader() const { return NULL; }
	virtual void print(std::ostream& where) const;
	const AbstractHeader * getPreviousHeader() const {
		return prev;
	}

protected:
	const unsigned char * data;
	unsigned int data_len;
	const AbstractHeader * prev;
};

inline std::ostream& operator<< (std::ostream& out, const AbstractHeader& hd) {
	hd.print(out);
	return out;
}

class EthernetHeader : public AbstractHeader {
public:
	EthernetHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: AbstractHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "Ethernet"; }
	virtual AbstractHeader * createNextHeader() const;
	virtual void print(std::ostream& where) const;
};

class IpHeader : public AbstractHeader {
public:
	IpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: AbstractHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "IP"; }
	virtual AbstractHeader * createNextHeader() const;
	virtual void print(std::ostream& where) const;
};

class TcpHeader : public AbstractHeader {
public:
	TcpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: AbstractHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "TCP"; }
	virtual AbstractHeader * createNextHeader() const;
	virtual void print(std::ostream& where) const;
};

class UdpHeader : public AbstractHeader {
public:
	UdpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: AbstractHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "UDP"; }
	virtual AbstractHeader * createNextHeader() const;
	virtual void print(std::ostream& where) const;
};

class IcmpHeader : public AbstractHeader {
public:
	IcmpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: AbstractHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "ICMP"; }
	virtual AbstractHeader * createNextHeader() const;
	virtual void print(std::ostream& where) const;
};

class IgmpHeader : public AbstractHeader {
public:
	IgmpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: AbstractHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "IGMP"; }
};

class ArpHeader : public AbstractHeader {
public:
	ArpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: AbstractHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "ARP"; }
};

class UnknownHeader : public AbstractHeader {
public:
	UnknownHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: AbstractHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "Unknown"; }
};

class PayloadData : public AbstractHeader {
public:
	PayloadData(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: AbstractHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "Data"; }
};

} // namespace filter

#endif // HEADERS_H_25E85D1E_4C87_11E2_BB32_7BDCB76BDF0B_

