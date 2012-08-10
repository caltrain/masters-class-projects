#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
#define LINE_LEN 6
#define SIZE_ETHERNET 14

static int count = 0;
int tcpCount = 0;
int udpCount = 0;
int ipCount = 0;
int icmpCount = 0;
int ProtocolList[1000][2];

void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	//const u_char *packet;
	static int i;	
	int k;
	const u_char *buff;
	int match=0;
	struct ether_header *eptr; 
	struct ip *iphdr = NULL;          /* IPv4 Header                            */
	struct tcphdr *tcphdr; 
	struct udphdr *udphdr; 
	//unsigned long current_ts=0;	 
 	    /* TCP Header                             */
	
	
	 printf("\nepoch time is %ld:%ld (%ld)\n",header->ts.tv_sec, header->ts.tv_usec, header->len);          	
	 
	printf("destination address :"); 
	for (i=1; (i < header->caplen + 1 ) ; i++)
	{	
		printf("%.2x: ", pkt_data[i-1]);
		if ( ((i % LINE_LEN) == 0)) 
		{
			printf("\n");
			break;
		}
		
		 
	}
	
	printf("source address :");
	for(k=i+1;(k < header->caplen + 1 ) ; k++)
	{
		
		printf("%.2x: ", pkt_data[k-1]);
		if ( (k % LINE_LEN) == 0)
		{
			printf("\n");
			break;
		}
	}
	 
	 iphdr = (struct ip*)(pkt_data + sizeof(struct ether_header));
	fprintf(stdout," prot %u \n ",iphdr->ip_p);
	static int ts;
	static int ft;
	static int st;
	static int es;
	//int ts=0;
	printf("networkprotocol\t\tpackets\n");
	
	switch(iphdr->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			tcpCount++;
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			udpCount++;
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			icmpCount++;
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			ipCount++;
			return;
		default:
			printf("   Protocol: unknown %d \n", iphdr->ip_p);
			return;
	} 
	
	/*for(i=0; ; i++)
	{
		if(iphdr->ip_p ==  ProtocolList[i][0] )
		{
			ProtocolList[i][1]++;
			printf("\ndone registering in protocol list\n");
			break;
		}
		else
		{
			ProtocolList[i][0] = iphdr->ip_p;
			ProtocolList[i][1] = 1;
			printf("\ndone registering in protocol list\n");
			break;
		}	
	}*/
	iphdr = (struct ip *)(pkt_data+12);
	
 	tcphdr = (struct tcphdr *)(pkt_data+sizeof(struct ether_header)+sizeof(struct ip));
	//printf("   ACK: %u\n", ntohl(tcphdr->th_ack) ); 
 //printf("   SEQ: %u\n", ntohl(tcphdr->th_seq) );
printf("   SRC IP: %s\n", inet_ntoa(iphdr->ip_dst)); 
iphdr = (struct ip *)(pkt_data+12+14); 

 printf("   DST IP: %s\n", inet_ntoa(iphdr->ip_src)); 
 printf("   SRC PORT: %u\n", ntohs(tcphdr->th_sport) ); 
 printf("   DST PORT: %u\n", ntohs(tcphdr->th_dport) ); 
 printf("   SRC PORT: %u\n", ntohs(udphdr->uh_sport) ); 
 printf("   DST PORT: %u\n", ntohs(udphdr->uh_dport) ); 
 
    	count++;
	printf("packet number is %d\n",count);
	
    printf("Date and time of the capture is: %s",ctime(&header->ts.tv_sec) );
	
}
int main(int argc, char **argv) 
{ 
	unsigned int pkt_counter=0;   // packet counter 
	unsigned long byte_counter=0; //total bytes seen in entire trace 
	unsigned long cur_counter=0; //counter for current 1-second interval 
	unsigned long max_volume = 0;  //max value of bytes in one-second interval 
	unsigned long current_ts=0;
	struct pcap_pkthdr header;
	
	//check command line arguments 
	if (argc < 2) 
	{ 
	fprintf(stderr, "Usage: %s [input pcaps]\n", argv[0]); 
	exit(1); 
	} 
	//open the pcap file 
	pcap_t *handle; 
	char errbuf[PCAP_ERRBUF_SIZE]; //not sure what to do with this, oh well 
	handle = pcap_open_offline(argv[1], errbuf);   //call pcap library function 
	if (handle == NULL) 
	{ 
	fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf); 
	return(2); 
	}
	//u_char *user = "the message ";

	pcap_loop(handle, 0, packet_handler, NULL);
	
		
	printf("Total number of packets is %d \n\n", count);
	printf("Protocol Summary:\n");
	printf("Protocol\t Number of Packets\n");
	printf(" TCP\t\t %d \n", tcpCount++);
	printf(" UDP\t\t %d \n", udpCount++);
	printf(" ICMP\t\t %d \n", icmpCount++);
	printf(" IP\t\t %d \n", ipCount++);
	pcap_close(handle);
	return 0;
} 

