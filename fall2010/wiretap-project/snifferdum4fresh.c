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
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
#define LINE_LEN 6
#include <time.h>
static int count = 0;

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
	/*if((int)iphdr->ip_p==26)
	ts++;
	printf("26\t\t %d\n",ts);

	if(iphdr->ip_p==52)
	ft++;
	printf("52\t\t %d\n",ft);
	if(iphdr->ip_p==62)
	st++;
	printf("62\t\t %d\n",st);
	if(iphdr->ip_p==806)
	es++;
	printf("806\t\t %d\n",es);*/
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
	
    printf("Start time and date of the capture is: %s",ctime(&header->ts.tv_sec) );
	
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
	pcap_close(handle);
		
	printf("number of packets is %d\n",count);
	return 0;
} 

