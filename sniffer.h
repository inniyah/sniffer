#ifndef SNIFFER_H_35C874BC_4DD1_11E2_AD2F_1BC708A5F99E_
#define SNIFFER_H_35C874BC_4DD1_11E2_AD2F_1BC708A5F99E_

struct pcap_pkthdr;

namespace filter {

class Sniffer {

public:
	Sniffer() {
	}
	virtual ~Sniffer() {
	}
	void loop(const char* devname);

protected:
	virtual void newPacket(const unsigned char * buffer, int size);

private:
	static void process_packet(unsigned char* arg, const struct pcap_pkthdr * header, const unsigned char * buffer);
};

}

#endif // SNIFFER_H_35C874BC_4DD1_11E2_AD2F_1BC708A5F99E_

