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
	in_addr_t  value;
public:
	inline IpAddress() : value(0)  { }
	inline IpAddress(in_addr_t  v) : value(v) { }
	inline operator in_addr_t() const { return value; }
	in_addr_t operator=(in_addr_t v) { return value = v; }
};

std::ostream& operator<< (std::ostream& out, const IpAddress & v);

class PortNumber {
private:
	u_int16_t value;
public:
	inline PortNumber() : value(0) { }
	inline PortNumber(u_int16_t v) : value(v) { }
	inline operator u_int16_t() const { return value; }
	u_int16_t operator=(u_int16_t v) { return value = v; }
};

std::ostream& operator<< (std::ostream& out, const PortNumber & v);

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
	AbstractHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
		: data((unsigned char *)buffer), data_len(len), prev(prev_header) { }
	virtual ~AbstractHeader() { }

	virtual const char * getTypeName() const = 0;
	virtual unsigned int getTypeID() const = 0;

	virtual const char * getHeaderName() const = 0;
	virtual const unsigned int getLayers() const = 0;
	virtual AbstractHeader * createNextHeader() const { return NULL; }
	virtual AbstractHeader * clone () const = 0;
	virtual void print(std::ostream& where) const;
	inline const AbstractHeader * getPreviousHeader() const { return prev; }

	// Extract relevant info from headers
	virtual const unsigned char * getMacAddress() const { return NULL; }
	virtual const in_addr_t getIpAddress() const { return 0; }
	virtual const u_int16_t getPortNumber() const { return 0; }

protected:
	const unsigned char * data;
	unsigned int data_len;
	const AbstractHeader * prev;

	static unsigned int next_id;
};

inline std::ostream& operator<< (std::ostream& out, const AbstractHeader& hd) {
	hd.print(out);
	return out;
}

template <typename DERIVED>
class HeaderAux : public AbstractHeader {
public:
	inline HeaderAux(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
			: AbstractHeader(buffer, len, prev_header) {
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

	virtual AbstractHeader *clone () const {
		return new DERIVED(static_cast<DERIVED const &>(*this));
	}

private:
	static unsigned int id;
};

class EthernetHeader : public HeaderAux<EthernetHeader> {
public:
	EthernetHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
			: HeaderAux<EthernetHeader>(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "Ethernet"; }
	virtual const unsigned int getLayers() const { return PHYSICAL_LAYER + DATA_LINK_LAYER; }
	virtual AbstractHeader * createNextHeader() const;
	virtual void print(std::ostream& where) const;
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header) {
		return new EthernetHeader(buffer, len, prev_header);
	}
};

class IpHeader : public HeaderAux<IpHeader> {
public:
	IpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
			: HeaderAux<IpHeader>(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "IP"; }
	virtual const unsigned int getLayers() const { return NETWORK_LAYER; }
	virtual AbstractHeader * createNextHeader() const;
	virtual void print(std::ostream& where) const;
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header) {
		return new IpHeader(buffer, len, prev_header);
	}
};

class TcpHeader : public HeaderAux<TcpHeader> {
public:
	TcpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
			: HeaderAux<TcpHeader>(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "TCP"; }
	virtual const unsigned int getLayers() const { return TRANSPORT_LAYER; }
	virtual AbstractHeader * createNextHeader() const;
	virtual void print(std::ostream& where) const;
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header) {
		return new TcpHeader(buffer, len, prev_header);
	}
};

class UdpHeader : public HeaderAux<UdpHeader> {
public:
	UdpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
			: HeaderAux<UdpHeader>(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "UDP"; }
	virtual const unsigned int getLayers() const { return TRANSPORT_LAYER; }
	virtual AbstractHeader * createNextHeader() const;
	virtual void print(std::ostream& where) const;
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header) {
		return new UdpHeader(buffer, len, prev_header);
	}
};

class IcmpHeader : public HeaderAux<IcmpHeader> {
public:
	IcmpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
			: HeaderAux<IcmpHeader>(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "ICMP"; }
	virtual const unsigned int getLayers() const { return NETWORK_LAYER; }
	virtual AbstractHeader * createNextHeader() const;
	virtual void print(std::ostream& where) const;
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header) {
		return new IcmpHeader(buffer, len, prev_header);
	}
};

class IgmpHeader : public HeaderAux<IgmpHeader> {
public:
	IgmpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
			: HeaderAux<IgmpHeader>(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "IGMP"; }
	virtual const unsigned int getLayers() const { return NETWORK_LAYER; }
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header) {
		return new IgmpHeader(buffer, len, prev_header);
	}
};

class ArpHeader : public HeaderAux<ArpHeader> {
public:
	ArpHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
			: HeaderAux<ArpHeader>(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "ARP"; }
	virtual const unsigned int getLayers() const { return DATA_LINK_LAYER + NETWORK_LAYER; }
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

class UnknownHeader : public HeaderAux<UnknownHeader> {
public:
	UnknownHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
			: HeaderAux<UnknownHeader>(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "Unknown"; }
	virtual const unsigned int getLayers() const { return 0; }
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header) {
		return new UnknownHeader(buffer, len, prev_header);
	}
};

class PayloadData : public HeaderAux<PayloadData> {
public:
	PayloadData(const void * buffer, unsigned int len, const AbstractHeader * prev_header)
			: HeaderAux<PayloadData>(buffer, len, prev_header) { }
	virtual const char * getHeaderName() const { return "Data"; }
	virtual const unsigned int getLayers() const { return PAYLOAD_DATA; }
	static AbstractHeader * createHeader(const void * buffer, unsigned int len, const AbstractHeader * prev_header) {
		return new PayloadData(buffer, len, prev_header);
	}
};

} // namespace filter

#endif // HEADERS_H_25E85D1E_4C87_11E2_BB32_7BDCB76BDF0B_

