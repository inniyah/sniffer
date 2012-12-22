#ifndef ABSTRACT_SNIFFER_H_
#define ABSTRACT_SNIFFER_H_

struct ethhdr;
struct iphdr;
struct tcphdr;
struct udphdr;
struct icmphdr;
struct arphd;

class AbstractSniffer {

public:
	AbstractSniffer();
	virtual ~AbstractSniffer();
	void loop(const char* devname);

protected:
	virtual void eth_packet(const struct ethhdr & eth, const unsigned char * payload_buffer, int payload_size) { }
	virtual void tcp_packet(const struct ethhdr & eth, const struct iphdr & iph, const struct tcphdr & tcph, const unsigned char * payload_buffer, int payload_size) { }
	virtual void udp_packet(const struct ethhdr & eth, const struct iphdr & iph, const struct udphdr & udph, const unsigned char * payload_buffer, int payload_size) { }
	virtual void icmp_packet(const struct ethhdr & eth, const struct iphdr & iph, const struct icmphdr & icmph, const unsigned char * payload_buffer, int payload_size) { }
	virtual void arp_packet(const struct ethhdr & eth, const struct arphdr & arph,  const unsigned char * data_buffer, int data_size) { }

	virtual void stats_updated();

	unsigned int stat_eth;
	unsigned int stat_ip;
	unsigned int stat_tcp;
	unsigned int stat_udp;
	unsigned int stat_icmp;
	unsigned int stat_arp;
	unsigned int stat_igmp;

private:
	inline void eth_packet(const unsigned char* buffer, int size);
	inline void tcp_packet(const unsigned char* buffer, int size);
	inline void udp_packet(const unsigned char* buffer, int size);
	inline void icmp_packet(const unsigned char* buffer, int size);
	inline void arp_packet(const unsigned char* buffer, int size);

	static void process_packet(unsigned char* arg, const struct pcap_pkthdr * header, const unsigned char * buffer);
};

#endif // ABSTRACT_SNIFFER_H_

