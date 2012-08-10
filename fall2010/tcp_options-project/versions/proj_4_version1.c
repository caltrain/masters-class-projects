#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#define __FAVOR_BSD
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>
#include <stdbool.h>
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
#define LINE_LEN 6
#include <time.h>
/* Ethernet header */
/*struct sniff_ethernet {
        u_char  ether_dhost[6];    /* destination host address */
       // u_char  ether_shost[6];    /* source host address */
       // u_short ether_type;                     /* IP? ARP? RARP? etc */
//};

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
static int ctos_total=0;
static int stoc_total=0;
static int c2sack=0;
static int c2srst=0;
static int c2ssyn=0;
static int c2spsh=0;
static int c2sfin=0;
static int c2surg=0;
static int s2cack=0;
static int s2crst=0;
static int s2csyn=0;
static int s2cpsh=0;
static int s2cfin=0;
static int s2curg=0;
long int start,end;
long int size[1000];

static int to=0;
static int p, p1;
long int ipsrc[500];
long int ipdst[500];
long int tsport[500];
static int count26;
static int count52;
static int count62;
static int count806;
static int ip;
static int count1;
static int count2;
static int tcp;
static int udp=1;
static int p;
unsigned int countseq[1000];
long int ethtype[1000];
unsigned int proto[1000];
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;
u_char *ptr;
	int size_ip;
	int size_tcp;
int i;

//int sequence[1000];
ip = (struct sniff_ip*)(pkt_data + 14);
size_ip = IP_HL(ip)*4;
if(size_ip==8 || size_ip==32|| size_ip==0)
	{

	return;
	}
tcp = (struct sniff_tcp*)(pkt_data + 14 + size_ip);
	size_tcp = TH_OFF(tcp)*4;
if(ip->ip_p==6)
{

//printf( "%s\n\n", inet_ntoa(ip->ip_src));
	//printf("%s\n\n", inet_ntoa(ip->ip_dst));
	if(ntohs(tcp->th_sport) >1000 && ntohs(tcp->th_dport) <1000)
	{
		ctos_total++;
		if((tcp->th_flags & TH_ACK)!=0)
			{
			c2sack++;
			}
			if((tcp->th_flags & TH_RST)!=0)
			{

			c2srst++;
			}
			if((tcp->th_flags & TH_SYN)!=0)
			{
			c2ssyn++;
			countseq[ctos_total]=ntohs(tcp->th_seq);
			}
			if((tcp->th_flags & TH_PUSH)!=0)
			{
			c2spsh++;
			}
			if((tcp->th_flags & TH_FIN)!=0)
			{
			c2sfin++;
			}
			if((tcp->th_flags & TH_URG)!=0)
			{
			c2surg++;
			}
		//printf("size of packet client to server %d is :%d\n",ctos_total+,header->len); //Size of packet is here
	}
	if(ntohs(tcp->th_sport) <1000 && ntohs(tcp->th_dport) > 1000)
	{
		stoc_total++;
		if((tcp->th_flags & TH_ACK)!=0)
			{

			s2cack++;
			}
			if((tcp->th_flags & TH_RST)!=0)
			{

			s2crst++;
			}
			if((tcp->th_flags & TH_SYN)!=0)
			{
			s2csyn++;
			}
			if((tcp->th_flags & TH_PUSH)!=0)
			{
			s2cpsh++;
			}
			if((tcp->th_flags & TH_FIN)!=0)
			{
			s2cfin++;
			}
			if((tcp->th_flags & TH_URG)!=0)
			{
			s2curg++;
			}
			//printf("size of packet server to client %d is :%d\n",stoc_total,header->len); //Size of packet is here
	}

}
}
int main(int argc, char **argv)
{
	int i,j,src;
	int max;
	int min;
	float avg=0.0,sum=0.0;
	unsigned int pkt_counter=0;   // packet counter
	unsigned long byte_counter=0; //total bytes seen in entire trace
	unsigned long cur_counter=0; //counter for current 1-second interval
	unsigned long max_volume = 0;  //max value of bytes in one-second interval
	unsigned long current_ts=0;
	struct pcap_pkthdr header;

	if (argc < 2)
	{
	fprintf(stderr, "Usage: %s [input pcaps]\n", argv[0]);
	exit(1);
	}
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_offline(argv[1], errbuf);
	if (handle == NULL)
	{
	fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf);
	return(2);
	}
	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf("this is not an Ethernet\n");
		exit(EXIT_FAILURE);
	}
pcap_loop(handle, 0, packet_handler, NULL);
		pcap_close(handle);
printf("number of packets from client to server:%d\n",ctos_total);
printf("number of packets from server to client:%d\n",stoc_total);
	//for(i=1;i<=ctos_total;i++)
			//printf("seq: %u\n",countseq[i]);       //Printing Sequence number here  *****************
	printf("\nClient to Server(%d):\n",ctos_total);
printf("\nTCP FLAGS\t#packets\n");
	printf("ack\t\t%d\n",c2sack);
	printf("rst\t\t%d\n",c2srst);
	printf("syn\t\t%d\n",c2ssyn);
	printf("push\t\t%d\n",c2spsh);
	printf("fin\t\t%d\n",c2sfin);
	printf("urg\t\t%d\n",c2surg);
	printf("\nServer to Client(%d):\n",stoc_total);
printf("\nTCP FLAGS\t#packets\n");
	printf("ack\t\t%d\n",s2cack);
	printf("rst\t\t%d\n",s2crst);
	printf("syn\t\t%d\n",s2csyn);
	printf("push\t\t%d\n",s2cpsh);
	printf("fin\t\t%d\n",s2cfin);
	printf("urg\t\t%d\n",s2curg);
}
