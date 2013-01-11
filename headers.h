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

// Basic Types

class MacAddress {
private: 
	unsigned char address[ETH_ALEN];
public:
	inline MacAddress();
	inline MacAddress(const unsigned char * v);
	inline operator const unsigned char * () const { return address; }
	const unsigned char * operator=(const unsigned char * v);
	bool less (const unsigned char * other, bool equal) const;
	bool equal (const unsigned char * other) const;
	inline bool operator< (const unsigned char * other) const {
		return less (other, false);
	}
	inline bool operator<= (const unsigned char * other) const {
		return less (other, true);
	}
	inline bool operator> (const unsigned char * other) const {
		return ! less (other, true);
	}
	inline bool operator>= (const unsigned char * other) const {
		return ! less (other, false);
	}
	inline bool operator== (const unsigned char * other) const {
		return equal (other);
	}
	inline bool operator!= (const unsigned char * other) const {
		return ! equal (other);
	}
};

std::ostream& operator<< (std::ostream& out, const MacAddress & v);

class IpAddress {
private:
	in_addr_t value;
public:
	inline IpAddress() : value(0)  { }
	inline IpAddress(in_addr_t  v) : value(v) { }
	inline operator in_addr_t() const { return value; }
	in_addr_t operator=(in_addr_t v) { return value = v; }
};

std::ostream& operator<< (std::ostream& out, const IpAddress & v);

class Ip6Address {
private:
	struct in6_addr address;
public:
	inline Ip6Address();
	inline Ip6Address(const struct in6_addr & a);
	inline const struct in6_addr &getAddress() const { return address; }
};

std::ostream& operator<< (std::ostream& out, const Ip6Address & v);

class PortNumber {
private:
	u_int16_t value;
public:
	inline PortNumber() : value(0) { }
	inline PortNumber(u_int16_t v) : value(v) { }
	inline operator u_int16_t() const { return value; }
	u_int16_t operator=(u_int16_t v) { return value = v; }
};

// Separate semantically TCP and UDP ports even though they're the same type

class TCPPortNumber : public PortNumber {
};

class UDPPortNumber : public PortNumber {
};

std::ostream& operator<< (std::ostream& out, const PortNumber & v);

// Abstract Header

enum {
	PHYSICAL_LAYER =     1 << 0,
	DATA_LINK_LAYER =    1 << 1, // Frames
	NETWORK_LAYER =      1 << 2, // Packets
	TRANSPORT_LAYER =    1 << 3, // Flow control
	SESSION_LAYER =      1 << 4, // Session support, authentication
	PRESENTATION_LAYER = 1 << 5, // Translation, unit conversion, encryption
	APPLICATION_LAYER =  1 << 6, // Program
	PAYLOAD_DATA =       1 << 7, // Data contents
};

class AbstractHeader {
public:
	AbstractHeader(const void * buffer, unsigned int len)
		: data((unsigned char *)buffer), data_len(len), prev(NULL), next(NULL) { }
	virtual ~AbstractHeader() {  // Deleting any node deletes the whole list
		if (next) {
			next->prev = NULL;
			delete next;
		}
		if (prev) {
			prev->next = NULL;
			delete prev;
		}
	}

	virtual const char * getTypeName() const = 0;
	virtual unsigned int getTypeID() const = 0;

	virtual const char * getHeaderName() const = 0;
	virtual const unsigned int getLayers() const = 0;
	virtual void print(std::ostream& where) const;

	inline AbstractHeader * getPreviousHeader() const {
		return prev;
	}
	inline AbstractHeader * getNextHeader() { // Lazy creation
		if (!next) {
			next = createNextHeader();
			if (next) next->prev = this;
		}
		return next;
	}

	// Extract relevant info from headers
	virtual const unsigned char * getMacAddress() const { return NULL; }
	virtual const in_addr_t getIpAddress() const { return 0; }
	virtual const u_int16_t getPortNumber() const { return 0; }

protected:
	virtual AbstractHeader * createNextHeader() const { return NULL; }

	const unsigned char * data;
	unsigned int data_len;
	AbstractHeader * prev;
	AbstractHeader * next;

	static unsigned int next_id;

private:
	// Can't be copied
	AbstractHeader(const AbstractHeader &other);
	AbstractHeader &operator=(const AbstractHeader &other);
};

inline std::ostream& operator<< (std::ostream& out, const AbstractHeader& hd) {
	hd.print(out);
	return out;
}

template <typename DERIVED>
class HeaderAux : public AbstractHeader {
public:
	inline HeaderAux(const void * buffer, unsigned int len)
			: AbstractHeader(buffer, len) {
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

private:
	static unsigned int id;
};

// Headers for different protocols

class EthernetHeader : public HeaderAux<EthernetHeader> {
public:
	EthernetHeader(const void * buffer, unsigned int len)
			: HeaderAux<EthernetHeader>(buffer, len) { }
	virtual const char * getHeaderName() const { return "Ethernet"; }
	virtual const unsigned int getLayers() const { return PHYSICAL_LAYER + DATA_LINK_LAYER; }
	virtual void print(std::ostream& where) const;
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, AbstractHeader * prev_header) {
		return new EthernetHeader(buffer, len);
	}
protected:
	virtual AbstractHeader * createNextHeader() const;
};

class IpHeader : public HeaderAux<IpHeader> {
public:
	IpHeader(const void * buffer, unsigned int len)
			: HeaderAux<IpHeader>(buffer, len) { }
	virtual const char * getHeaderName() const { return "IP"; }
	virtual const unsigned int getLayers() const { return NETWORK_LAYER; }
	virtual void print(std::ostream& where) const;
	static AbstractHeader * createHeader(const void * buffer, unsigned int len) {
		return new IpHeader(buffer, len);
	}
protected:
	virtual AbstractHeader * createNextHeader() const;
};

class TcpHeader : public HeaderAux<TcpHeader> {
public:
	TcpHeader(const void * buffer, unsigned int len)
			: HeaderAux<TcpHeader>(buffer, len) { }
	virtual const char * getHeaderName() const { return "TCP"; }
	virtual const unsigned int getLayers() const { return TRANSPORT_LAYER; }
	virtual void print(std::ostream& where) const;
	static AbstractHeader * createHeader(const void * buffer, unsigned int len) {
		return new TcpHeader(buffer, len);
	}
protected:
	virtual AbstractHeader * createNextHeader() const;
};

class UdpHeader : public HeaderAux<UdpHeader> {
public:
	UdpHeader(const void * buffer, unsigned int len)
			: HeaderAux<UdpHeader>(buffer, len) { }
	virtual const char * getHeaderName() const { return "UDP"; }
	virtual const unsigned int getLayers() const { return TRANSPORT_LAYER; }
	virtual void print(std::ostream& where) const;
	static AbstractHeader * createHeader(const void * buffer, unsigned int len) {
		return new UdpHeader(buffer, len);
	}
protected:
	virtual AbstractHeader * createNextHeader() const;
};

class IcmpHeader : public HeaderAux<IcmpHeader> {
public:
	IcmpHeader(const void * buffer, unsigned int len)
			: HeaderAux<IcmpHeader>(buffer, len) { }
	virtual const char * getHeaderName() const { return "ICMP"; }
	virtual const unsigned int getLayers() const { return NETWORK_LAYER; }
	virtual void print(std::ostream& where) const;
	static AbstractHeader * createHeader(const void * buffer, unsigned int len) {
		return new IcmpHeader(buffer, len);
	}
protected:
	virtual AbstractHeader * createNextHeader() const;
};

class IgmpHeader : public HeaderAux<IgmpHeader> {
public:
	IgmpHeader(const void * buffer, unsigned int len)
			: HeaderAux<IgmpHeader>(buffer, len) { }
	virtual const char * getHeaderName() const { return "IGMP"; }
	virtual const unsigned int getLayers() const { return NETWORK_LAYER; }
	static AbstractHeader * createHeader(const void * buffer, unsigned int len) {
		return new IgmpHeader(buffer, len);
	}
};

class ArpHeader : public HeaderAux<ArpHeader> {
public:
	ArpHeader(const void * buffer, unsigned int len)
			: HeaderAux<ArpHeader>(buffer, len) { }
	virtual const char * getHeaderName() const { return "ARP"; }
	virtual const unsigned int getLayers() const { return DATA_LINK_LAYER + NETWORK_LAYER; }
	virtual void print(std::ostream& where) const;
	static AbstractHeader * createHeader(const void * buffer, unsigned int len);
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
	ArpEthIpHeader(const void * buffer, unsigned int len)
			: ArpHeader(buffer, len) { }
	virtual const char * getHeaderName() const { return "ARP (Ethernet, IP4)"; }
	virtual void print(std::ostream& where) const;
};

class UnknownHeader : public HeaderAux<UnknownHeader> {
public:
	UnknownHeader(const void * buffer, unsigned int len)
			: HeaderAux<UnknownHeader>(buffer, len) { }
	virtual const char * getHeaderName() const { return "Unknown"; }
	virtual const unsigned int getLayers() const { return 0; }
	static AbstractHeader * createHeader(const void * buffer, unsigned int len) {
		return new UnknownHeader(buffer, len);
	}
};

class PayloadData : public HeaderAux<PayloadData> {
public:
	PayloadData(const void * buffer, unsigned int len)
			: HeaderAux<PayloadData>(buffer, len) { }
	virtual const char * getHeaderName() const { return "Data"; }
	virtual const unsigned int getLayers() const { return PAYLOAD_DATA; }
	static AbstractHeader * createHeader(const void * buffer, unsigned int len) {
		return new PayloadData(buffer, len);
	}
};

} // namespace filter

#endif // HEADERS_H_25E85D1E_4C87_11E2_BB32_7BDCB76BDF0B_

