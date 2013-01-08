#ifndef HEADERS_H_25E85D1E_4C87_11E2_BB32_7BDCB76BDF0B_
#define HEADERS_H_25E85D1E_4C87_11E2_BB32_7BDCB76BDF0B_

#include <iostream>
#include <typeinfo>

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

class AbstractIdBase {
public:
	virtual const char * getTypeName() const = 0;
	virtual unsigned int getTypeID() const = 0;

	virtual void print(std::ostream& where) const = 0;

	inline bool operator< (const AbstractIdBase &other) const {
		return less (other, false);
	}

	inline bool operator<= (const AbstractIdBase &other) const {
		return less (other, true);
	}

	inline bool operator> (const AbstractIdBase &other) const {
		return ! less (other, true);
	}

	inline bool operator>= (const AbstractIdBase &other) const {
		return ! less (other, false);
	}

	inline bool operator== (const AbstractIdBase &other) const {
		return equal (other);
	}

	inline bool operator!= (const AbstractIdBase &other) const {
		return ! equal (other);
	}

	virtual bool isSameType (const AbstractIdBase &other) const {
		return false;
	}

	enum {
		PHYSICAL_LAYER =     1 << 0, // Frames
		NETWORK_LAYER =      1 << 1, // Packets
		TRANSPORT_LAYER =    1 << 2, // Flow control
		SESSION_LAYER =      1 << 3, // Session support, authentication
		PRESENTATION_LAYER = 1 << 4, // Translation, unit conversion, encryption
		APPLICATION_LAYER =  1 << 5, // Program
	};

	virtual const unsigned int getLayers() const { return 0; }

	virtual const unsigned char * getMacAddress() const { return NULL; }
	virtual const in_addr_t getIpAddress() const { return 0; }

protected:
	virtual bool less (const AbstractIdBase &other, bool equal) const = 0;
	virtual bool equal (const AbstractIdBase &other) const = 0;
	virtual AbstractIdBase *clone () const = 0;

	static unsigned int next_id;
};

template <typename DERIVED>
class AbstractId : public AbstractIdBase {
public:
	AbstractId() {
		if (id ==0) { id = ++next_id; }
	}

	static unsigned int ID() {
		if (id ==0) { id = ++next_id; }
		return id;
	}

	virtual const char * getTypeName() const {
		return typeid(DERIVED).name();
	}

	virtual unsigned int getTypeID() const {
		return id;
	}

	virtual AbstractIdBase *clone () const {
		return new DERIVED(static_cast<DERIVED const &>(*this));
	}

private:
	static unsigned int id;
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
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header) {
		return new EthernetHeader(buffer, len, prev_header);
	}
};

class IpHeader : public AbstractHeader {
public:
	IpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: AbstractHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "IP"; }
	virtual AbstractHeader * createNextHeader() const;
	virtual void print(std::ostream& where) const;
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header) {
		return new IpHeader(buffer, len, prev_header);
	}
};

class TcpHeader : public AbstractHeader {
public:
	TcpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: AbstractHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "TCP"; }
	virtual AbstractHeader * createNextHeader() const;
	virtual void print(std::ostream& where) const;
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header) {
		return new TcpHeader(buffer, len, prev_header);
	}
};

class UdpHeader : public AbstractHeader {
public:
	UdpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: AbstractHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "UDP"; }
	virtual AbstractHeader * createNextHeader() const;
	virtual void print(std::ostream& where) const;
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header) {
		return new UdpHeader(buffer, len, prev_header);
	}
};

class IcmpHeader : public AbstractHeader {
public:
	IcmpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: AbstractHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "ICMP"; }
	virtual AbstractHeader * createNextHeader() const;
	virtual void print(std::ostream& where) const;
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header) {
		return new IcmpHeader(buffer, len, prev_header);
	}
};

class IgmpHeader : public AbstractHeader {
public:
	IgmpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: AbstractHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "IGMP"; }
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header) {
		return new IgmpHeader(buffer, len, prev_header);
	}
};

class ArpHeader : public AbstractHeader {
public:
	ArpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: AbstractHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "ARP"; }
	virtual void print(std::ostream& where) const;
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header);
};

struct arphdr_eth_ipv4
{
	unsigned char ar_sha[ETH_ALEN];	/* Sender hardware address.  */
	unsigned char ar_spa[4];	/* Sender IP address.  */
	unsigned char ar_tha[ETH_ALEN];	/* Target hardware address.  */
	unsigned char ar_tpa[4];	/* Target IP address.  */
};

class ArpEthIpHeader : public ArpHeader {
public:
	ArpEthIpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: ArpHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "ARP (Ethernet, IP4)"; }
	virtual void print(std::ostream& where) const;
};

class UnknownHeader : public AbstractHeader {
public:
	UnknownHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: AbstractHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "Unknown"; }
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header) {
		return new UnknownHeader(buffer, len, prev_header);
	}
};

class PayloadData : public AbstractHeader {
public:
	PayloadData(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: AbstractHeader(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "Data"; }
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header) {
		return new PayloadData(buffer, len, prev_header);
	}
};

} // namespace filter

#endif // HEADERS_H_25E85D1E_4C87_11E2_BB32_7BDCB76BDF0B_

