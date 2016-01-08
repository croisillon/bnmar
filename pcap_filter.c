#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#define PCAP_FILE "123.pcap"

void dump_packet (const unsigned char *packet, struct pcap_pkthdr header);

int main(int argc, char *argv[])
{

	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;

	if ( (pcap = pcap_open_offline(PCAP_FILE, errbuf)) == NULL )
	{
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
	}

	while ( (packet = pcap_next(pcap,&header)) != NULL )
	{
		dump_packet(packet, header);
	}

	return 0;

}

void dump_packet (const unsigned char *packet, struct pcap_pkthdr header)
{
	struct timeval ts = header.ts;

	printf("%ld %ld\n",ts.tv_sec, ts.tv_usec);
}