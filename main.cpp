#include "sniffer.h"

#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main()
{
	pcap_if_t* alldevsp;
	pcap_if_t* device;
	char errbuf[100];
	char* devname;
	char devs[100][100];
	int count = 1;
	int n;

	// Get the list of available devices
	printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	printf("Done");

	// Print available devices
	printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}

	// Ask user which device to sniff
	printf("Enter the number of the device you want to sniff : ");
	scanf("%d", &n);
	devname = devs[n];

	filter::Sniffer sniffer;
	sniffer.loop(devname);

	return 0;
}

