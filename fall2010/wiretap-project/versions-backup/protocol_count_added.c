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
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
#define LINE_LEN 6
#include <time.h>
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
static int fin=0;
static int urg=0;
static int ece=0;
static int cwr=0;
long int start,end;
long int size[1000];
static int to=0;
static int p,p1;
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
static int udp;
long int ethtype[100];
unsigned int proto[100];
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	const struct ether_header *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;    
	ethernet=(struct ether_header*)pkt_data;        /* The TCP header */
	u_char *ptr;
	int size_ip;
	int size_tcp;
	int size_udp;
	int i;
	if(count==1)
	{
	printf("Start time and date of the capture is: %s\n",ctime(&header->ts.tv_sec)); 
	start=header->ts.tv_sec;
	}	
	end=header->ts.tv_sec;
	ethtype[p]=ntohs(ethernet->ether_type);
	p++;
	ip = (struct sniff_ip*)(pkt_data + 14);
	size_ip = IP_HL(ip)*4;
	if(size_ip==8 || size_ip==32 || size_ip==0)
	{
	size[count]=header->len;
	count++;
	return;
	}
	
	size[count]=header->len;
	fprintf(stdout,"source: %s \n",ether_ntoa((struct ether_header*)ethernet->ether_shost));
    	fprintf(stdout,"dest: %s \n",ether_ntoa((struct ether_header*)ethernet->ether_dhost));
	tcp = (struct sniff_tcp*)(pkt_data + 14 + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	struct udphdr *udph = (struct udphdr*)(pkt_data + 14 + size_ip);
	
	if (size_ip==0) 
	{

		ip = (struct sniff_ip*)(pkt_data + 12+14);
		
		fprintf(stdout," prot %u \n ",ip->ip_p);
		//ipdst[to]=inet_ntoa(ip->ip_src);
		//printf("       To: %s\n", ipdst[to]);
		//printf("       To: %s\n", inet_ntoa(ip->ip_src));
		
		ip = (struct sniff_ip*)(pkt_data + 12);
		//ipsrc[to]=inet_ntoa(ip->ip_dst);
		//printf("       From ipsrc: %s\n",ipsrc[to]);
		
		//to++;
		count++;	
		printf("packet number is %d\n",count);	
				
		return;
	}
	
	/* print source and destination IP addresses */
	else
	{
		if(ip->ip_p==6)
		{
		tsport[p]=ntohs(tcp->th_sport);
		printf("   Src port: %d\n",tsport[p]);
		p++;
		printf("   Dst port: %d\n", ntohs(tcp->th_dport));
			if((tcp->th_flags & TH_ACK)!=0)
			{
			//printf("flag %X\n",tcp->th_flags);
			ack++;
			}
			if((tcp->th_flags & TH_RST)!=0)
			{
			//printf("flag %X\n",tcp->th_flags);
			rst++;
			}
			if((tcp->th_flags & TH_SYN)!=0)
			{
			//printf("flag %X\n",tcp->th_flags);
			syn++;
			}
			if((tcp->th_flags & TH_PUSH)!=0)
			{
			//printf("flag %X\n",tcp->th_flags);
			psh++;
			}
			if((tcp->th_flags & TH_FIN)!=0)
			{
			//printf("flag %X\n",tcp->th_flags);
			fin++;
			}
			if((tcp->th_flags & TH_URG)!=0)
			{
			//printf("flag %X\n",tcp->th_flags);
			urg++;
			}
			if((tcp->th_flags & TH_ECE)!=0)
			{
			//printf("flag %X\n",tcp->th_flags);
			ece++;
			}
			if((tcp->th_flags & TH_CWR)!=0)
			{
			//printf("flag %X\n",tcp->th_flags);
			cwr++;
			}
		//printf("   Flag: RST\n");
		}
				
		if(ip->ip_p==17)
		{
		printf("   Src port: %d\n", ntohs(udph->uh_sport));
		printf("   Dst port: %d\n", ntohs(udph->uh_dport));
		//printf("   checksum %X\n", ntohs(udph->uh_len));
		printf("   length %d\n",ntohs(udph->uh_ulen));
		}
	
	proto[p]=ip->ip_p;
	p1++;
	ipsrc[to]=inet_ntoa(ip->ip_src);
	//to++;
	
	//
	to++;
	ipdst[to]=inet_ntoa(ip->ip_dst);
	printf("       To : %s\n", ipdst[to]);
	count++;
	
	
	printf("packet number is %d\n",count);
	
	}
	
}

		
int main(int argc, char **argv) 
{ 
	int i,j,src;
	int max;
	int min;
	float avg,sum;
	unsigned int pkt_counter=0;   // packet counter 
	unsigned long byte_counter=0; //total bytes seen in entire trace 
	unsigned long cur_counter=0; //counter for current 1-second interval 
	
	struct pcap_pkthdr header;
	
	//check command line arguments 
	if (argc < 2) 
	{ 
	fprintf(stderr, "Usage: %s [input pcaps]\n", argv[0]); 
	exit(1); 
	} 
	//open the pcap file 
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
	printf("\nTCP FLAGS\t#packets\n");
	printf("ack\t\t%d\n",ack);
	printf("rst\t\t%d\n",rst);
	printf("syn\t\t%d\n",syn);
	printf("push\t\t%d\n",psh);
	printf("fin\t\t%d\n",fin);
	printf("urg\t\t%d\n",urg);
	printf("ece\t\t%d\n",ece);
	printf("cwr\t\t%d\n",cwr);
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
	for(i=0;i<p;i++)
	{
		switch(ethtype[i])
		  {
			case 38:
			count26++;
			break;
			case 82:
			count52++;
			break;
			case 98:
			count62++;
			break;
			case 2054:
			count806++;
			break;
			case 2048:
			ip++;
			break;
		  }
	}
	for(i=0;i<p;i++)
	{
		switch(proto[i])
		{
		case 1:
		count1++;
		break;
		case 2:
		count2++;
		case 16:
		tcp++;
		break;
		case IPPROTO_UDP:
		udp++;
		break;
		}
	}
	printf("\ntransport protocol summary\n");
	printf("------------------------------------\n");
	printf("1\t\t%d\n",count1);
	printf("2\t\t%d\n",count2);
	printf("tcp\t\t%d\n",tcp);
	printf("udp\t\t%d\n",udp);
	printf("\nnetwork protocol summary\n");
	printf("------------------------------------\n");
	printf("protocol\t#packets\n");

	printf("26\t\t%d\n",count26);
	printf("52\t\t%d\n",count52);
	printf("62\t\t%d\n",count62);
	printf("806\t\t%d\n",count806);
	printf("ip\t\t%d\n",ip);
	
	printf("duration is %ld\n",end-start);		
	printf("average packet size is  %0.2f\n",avg);
	printf("minimum packet size is %d\n",min);
	printf("maximum packet size is %d\n",max);
	
	printf("number of packets is %d\n",count);
	
		
	return 0;
} 
