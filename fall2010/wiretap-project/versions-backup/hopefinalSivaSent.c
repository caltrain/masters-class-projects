#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#define __FAVOR_BSD
#include <netinet/ip.h>
#include <net/ethernet.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
#define LINE_LEN 6
#include <time.h>
/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};
static int count=0;
static int ack=0;
static int rst=0;
static int syn=0;
static int psh=0;
long int size[1000];
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	int size_ip;
	int size_tcp;
	int size_udp;
	
	printf("\nepoch time is %ld:%ld (%ld)\n",header->ts.tv_sec, header->ts.tv_usec, header->len);   
	size[count]=header->len;
	fprintf(stdout,"source: %s \n",ether_ntoa(ethernet->ether_shost));
    	fprintf(stdout,"dest: %s \n",ether_ntoa(ethernet->ether_dhost));
	ip = (struct sniff_ip*)(pkt_data + 14);
	size_ip = IP_HL(ip)*4;
	printf("size of ip %d", size_ip);
	tcp = (struct sniff_tcp*)(pkt_data + 14 + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	printf("size of tcp %d", size_tcp);
	struct udphdr *udph = (struct udphdr*)(pkt_data + 14 + size_ip);
	if (size_ip < 20) 
	{

		ip = (struct sniff_ip*)(pkt_data + 12+14);
		//printf("   * Invalid IP header length: %u bytes\n", size_ip);
		fprintf(stdout," prot %u \n ",ip->ip_p);
		printf("       To: %s\n", inet_ntoa(ip->ip_src));
		ip = (struct sniff_ip*)(pkt_data + 12);
		printf("         From: %s\n", inet_ntoa(ip->ip_dst));
		count++;	
		printf("packet number is %d\n",count);	
		printf("Start time and date of the capture is: %s",ctime(&header->ts.tv_sec) );			
		return;
	}
	
	/* print source and destination IP addresses */
	else
	{
		if(ip->ip_p==6)
		{
		printf("   Src port: %d\n", ntohs(tcp->th_sport));
		printf("   Dst port: %d\n", ntohs(tcp->th_dport));
			/*if((tcp->th_flags==TH_ACK))
			{
			//printf("flag %X\n",tcp->th_flags);
			ack++;
			}
			if((tcp->th_flags== TH_RST))
			{
			//printf("flag %X\n",tcp->th_flags);
			rst++;
			}
			if((tcp->th_flags==TH_SYN))
			{
			//printf("flag %X\n",tcp->th_flags);
			syn++;
			}
			if((tcp->th_flags==TH_PUSH))
			{
			//printf("flag %X\n",tcp->th_flags);
			psh++;
			}*/
		//printf("   Flag: RST\n");
		}
				
		if(ip->ip_p==17)
		{
		printf("   Src port: %d\n", ntohs(udph->uh_sport));
		printf("   Dst port: %d\n", ntohs(udph->uh_dport));
		printf("   checksum %X\n", ntohs(udph->uh_sum));
		printf("   length %d\n",udph->uh_ulen);
		}
	fprintf(stdout," prot %u \n ",ip->ip_p);
	printf("       To: %s\n", inet_ntoa(ip->ip_src));
	printf("       From: %s\n", inet_ntoa(ip->ip_dst));
	count++;
	printf("packet number is %d\n",count);
	printf("Start time and date of the capture is: %s",ctime(&header->ts.tv_sec) );
	}
}
	
int main(int argc, char **argv) 
{ 
	int i;
	int max;
	int min;
	float avg,sum;
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
	printf("ack\t%d\n",ack);
	printf("rst\t%d\n",rst);
	printf("syn\t%d\n",syn);
	printf("push\t%d\n",psh);
	min=size[0];
	max=size[0];
	for(i=0;i<count;i++)
	{
		
		if(size[i]<min)
		min=size[i];
		else if(size[i]>max)
		max=size[i];
		
	}
	for(i=0;i<count;i++)
	{
		sum+=size[i];
	}
		avg=sum/count;
	printf("average packet size is  %0.2f\n",avg);
	printf("minimum packet size is %d\n",min);
	printf("maximum packet size is %d\n",max);		
	printf("number of packets is %d\n",count);
	return 0;
} 
