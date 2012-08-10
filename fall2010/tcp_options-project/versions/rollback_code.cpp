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

#include <time.h>


#include <netinet/in.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <ctype.h>
#include <map>
#include <string>
#include <iostream>
#include <sstream>

#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
#define LINE_LEN 6

using namespace std;
map<string,int> ctos_uniq_pack_size;
    string ctos_pack_size;

map<string,int> stoc_uniq_pack_size;
    string stoc_pack_size;

map<string,int> ctos_uniq_adv_size;
    string ctos_adv_size;




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
static int c2s_syn_fin_ack, c2s_syn_ack, c2s_fin_ack, c2s_push;
static int c2s_along_push, c2s_push_syn, c2s_push_fin, c2s_push_ack, c2s_push_rst, c2s_push_urg ;
static int c2s_push_with[10];

static int s2c_syn_fin_ack, s2c_fin_ack, s2c_syn_ack, s2c_along_push;
static int s2c_push_fin, s2c_push_syn, s2c_push_ack, s2c_push_rst, s2c_push_urg;
static int s2c_urg_syn, s2c_urg_fin, s2c_urg_ack, s2c_urg_rst, s2c_urg_push ;
static int c2s_urg_ack, c2s_urg_rst, c2s_urg_syn, c2s_urg_fin, c2s_urg_push, c2s_along_urg, s2c_along_urg;
int ctos_last_seq_number, ctos_current_seq_number, ctos_wrap_count;
int stoc_last_seq_number, stoc_current_seq_number, stoc_wrap_count;
int packet_count = 0 , difference;
int ctos_nos_win_closed=0;
int c2s_syn_set =0;
int s2c_syn_set = 0;

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
static int push_count;
//static int p;
unsigned int countseq[1000];
long int ethtype[1000];
unsigned int proto[1000];


//************************************
//Function to print flags along with push flag
void print_push_along(int client)
{
	int i=0;
	if(client ==1)
	{
		if(c2s_push_syn== 1)
			printf(" SYN");
		if(c2s_push_fin== 1)
			printf(" FIN");
		if(c2s_push_ack== 1)
			printf(" ACK");
		if(c2s_push_urg== 1)
			printf(" URG");
		if(c2s_push_rst == 1)
			printf(" RST");

	}
	if(client ==0)
	{

		if(s2c_push_syn== 1)
			printf(" SYN");
		if(s2c_push_fin== 1)
			printf(" FIN");
		if(s2c_push_ack== 1)
			printf(" ACK");
		if(s2c_push_urg== 1)
			printf(" URG");
		if(s2c_push_rst == 1)
			printf(" RST");

	}
	return;
}

void print_urg_along(int client)
{
	int i=0;
	if(client ==1)
	{
		if(c2s_urg_syn== 1)
			printf(" SYN");
		if(c2s_urg_fin== 1)
			printf(" FIN");
		if(c2s_urg_ack== 1)
			printf(" ACK");
		if(c2s_urg_push == 1)
			printf(" PUSH");
		if(c2s_urg_rst == 1)
			printf(" RST");

	}
	if(client ==0)
	{

		if(s2c_urg_syn== 1)
			printf(" SYN");
		if(s2c_urg_fin== 1)
			printf(" FIN");
		if(s2c_urg_ack== 1)
			printf(" ACK");
		if(s2c_urg_push== 1)
			printf(" PUSH");
		if(s2c_urg_rst == 1)
			printf(" RST");

	}
	return;
}



void print_ctos()
{
	//*************************Client To Server***************************//
		printf("\n********************Client to Server(%d)****************************\n",ctos_total);
		printf("Number of packets from client to server:%d\n",ctos_total);
		printf("Unique packet sizes :\n");
		printf("Count\t\tPacket Size\n");
		map<string, int>::const_iterator iter;
		for (iter=ctos_uniq_pack_size.begin(); iter != ctos_uniq_pack_size.end(); ++iter)
			cout<< iter->second<<"\t\t"<<iter->first<<endl;

	printf("\nTCP FLAGS\t#packets\n");
		//printf("SYN FIN ACK \t%d\n",c2s_syn_fin_ack);
		printf("SYN\t\t%d\n",c2ssyn);
		printf("SYN ACK \t%d\n",c2s_syn_ack);
		printf("ACK\t\t%d\n",c2sack);
		printf("FIN\t\t%d\n",c2sfin);
		printf("FIN ACK \t %d\n",c2s_fin_ack);
		printf("PUSH\t\t%d\n",c2spsh);
	printf("Number of packets with other flags along with PUSH flag: %d ", c2s_along_push);

	printf("\nTypes of flag along with PUSH flag: ");
	print_push_along(1);    // parameter zero says "client"


		printf("\nURG\t\t%d\n",c2surg);
	printf("Number of packets with other flags along with URG flag: %d ", c2s_along_urg);

	printf("\nTypes of flag along with URG flag: ");
	print_urg_along(1);    // parameter zero says "client"

		printf("\nRST\t\t%d\n",c2srst);
	printf("\n Number of times sequence number wrap around occured: %d", ctos_wrap_count);

	printf("\nUnique values of receiver advertised window:\n");
		printf("\nCount \t\t Size\n");
	for (iter=ctos_uniq_adv_size.begin(); iter != ctos_uniq_adv_size.end(); ++iter)
			cout<< iter->second<<"\t\t"<<iter->first<<endl;

	printf("\n Number of times Window closed: %d ", ctos_nos_win_closed);
}

void print_stoc()
{
		//***********************Server to Client*****************************//

		printf("\n\n**********************Server to Client(%d)***********************\n",stoc_total);
		printf("Number of packets from server to client:%d\n",stoc_total);
		printf("Unique packet sizes :\n");
		printf("Count\t\tPacket Size\n");

		map<string, int>::const_iterator iter;
		for (iter=stoc_uniq_pack_size.begin(); iter != stoc_uniq_pack_size.end(); ++iter)
			cout<< iter->second<<"\t\t"<<iter->first<<endl;

		printf("\nTCP FLAGS\t#packets\n");
		printf("SYN FIN ACK \t%d\n",s2c_syn_fin_ack);
		printf("SYN\t\t%d\n",s2csyn);
		printf("SYN ACK \t%d\n",s2c_syn_ack);
		printf("ACK\t\t%d\n",s2cack);
		printf("FIN\t\t%d\n",s2cfin);
		printf("FIN ACK \t%d",s2c_fin_ack);

		printf("\nPUSH\t\t%d\n",s2cpsh);
		printf("\nNumber of packets with other flags along with PUSH flag: %d ", s2c_along_push);

		printf("\nTypes of flag along with PUSH flag: ");
		print_push_along(0);    // parameter 1 says "server to client"

	printf("\nURG\t\t%d\n",s2curg);
		printf("Number of packets with other flags along with URG flag: %d ", s2c_along_urg);

		printf("\nTypes of flag along with URG flag: ");
	print_urg_along(1);    // parameter zero says "client"

		printf("\nRST\t\t%d\n",s2crst);

	printf("\n Number of times sequence number wrap around occured: %d \n", stoc_wrap_count);
}//End of Print function

//initialize function for server to client varibales
void initialize_stoc()
{
	stoc_total=0;

	s2cack=0;
	s2crst=0;
	s2csyn=0;
	s2cpsh=0;
	s2cfin=0;
	s2curg=0;
	s2c_syn_fin_ack = 0; s2c_syn_ack = 0; s2c_fin_ack = 0; //s2c_push = 0;
	s2c_along_push = 0; s2c_push_syn = 0; s2c_push_fin = 0; s2c_push_ack = 0; s2c_push_rst = 0; s2c_push_urg = 0 ;
	//c2s_push_with[10];
	s2c_urg_ack  = 0; s2c_urg_rst = 0; s2c_urg_syn = 0; s2c_urg_fin = 0; s2c_urg_push = 0;
	s2c_along_urg = 0;
	s2c_along_urg = 0;
	stoc_last_seq_number =0;
	stoc_current_seq_number=0;
	stoc_wrap_count=0;

	//stoc_nos_win_closed=0;
	stoc_uniq_pack_size.clear();
}
void initialize_ctos()
{
	ctos_total=0;

	c2sack=0;
	c2srst=0;
	c2ssyn=0;
	c2spsh=0;
	c2sfin=0;
	c2surg=0;
	c2s_syn_fin_ack = 0; c2s_syn_ack = 0; c2s_fin_ack = 0; c2s_push = 0;
	c2s_along_push = 0; c2s_push_syn = 0; c2s_push_fin = 0; c2s_push_ack = 0; c2s_push_rst = 0; c2s_push_urg = 0 ;
	//c2s_push_with[10];
	c2s_urg_ack  = 0; c2s_urg_rst = 0; c2s_urg_syn = 0; c2s_urg_fin = 0; c2s_urg_push = 0;
	c2s_along_urg = 0;
	s2c_along_urg = 0;
	ctos_last_seq_number =0;
	ctos_current_seq_number=0;
	ctos_wrap_count=0;

	ctos_nos_win_closed=0;
	ctos_uniq_pack_size.clear();
	ctos_uniq_adv_size.clear();

	/*
	static int stoc_total=0;
	static int s2c_syn_fin_ack, s2c_fin_ack, s2c_syn_ack, s2c_along_push;
		static int s2c_push_fin, s2c_push_syn, s2c_push_ack, s2c_push_rst, s2c_push_urg;
	static int s2c_urg_syn, s2c_urg_fin, s2c_urg_ack, s2c_urg_rst, s2c_urg_push ;
	int stoc_last_seq_number, stoc_current_seq_number, stoc_wrap_count;

		static int s2cack=0;
		static int s2crst=0;
		static int s2csyn=0;
		static int s2cpsh=0;
		static int s2cfin=0;
	static int s2curg=0;

	long int start,end;
	long int size[1000];
	int packet_count = 0 , difference;

	*/
}

void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	packet_count++;
const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;
u_char *ptr;
	int size_ip;
	int size_tcp;
int i;
char temp_pack_len[10];

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
	if(ntohs(tcp->th_sport) >1023 && ntohs(tcp->th_dport) <1024)//******************* Client to s*************************
	{

		ctos_total++;
			if( (tcp->th_flags & (TH_ACK))!=0 && (tcp->th_flags & (TH_SYN) )!=0  )
			{
				if( (tcp->th_flags & (TH_FIN)) ==0 && (tcp->th_flags & (TH_PUSH)) ==0 && (tcp->th_flags & (TH_RST)) ==0 && (tcp->th_flags & (TH_URG)) ==0 )
				{
					c2s_syn_ack++;
				}
			}
			else if( (tcp->th_flags & (TH_FIN))!=0 && (tcp->th_flags & (TH_ACK))!=0 )
			{
				if( (tcp->th_flags & (TH_PUSH)) ==0 && (tcp->th_flags & (TH_URG)) ==0 && (tcp->th_flags & (TH_RST)) ==0 && (tcp->th_flags & (TH_SYN)) ==0 )
				{
					if(c2s_syn_set == 1)
					{
						c2s_fin_ack++;
						printf("\n\t Current Sequence Number: %u ", ntohl(tcp->th_seq) );
						print_ctos();
						initialize_ctos();
						c2s_syn_set = 0;    //Connection terminated so SYN set has been set to zero.!
					}
				}
			}
			else
			{
				if((tcp->th_flags & TH_ACK)!=0)
				{
					if( (tcp->th_flags & (TH_FIN)) ==0 && (tcp->th_flags & (TH_PUSH)) ==0 && (tcp->th_flags & (TH_RST)) ==0 && (tcp->th_flags & (TH_URG)) ==0 &&  (tcp->th_flags & (TH_SYN)) ==0 )
					{
						c2sack++;
					}
				}
				if((tcp->th_flags & TH_SYN)!=0)
				{
					if( (tcp->th_flags & (TH_FIN)) ==0 && (tcp->th_flags & (TH_PUSH)) ==0 && (tcp->th_flags & (TH_RST)) ==0 && (tcp->th_flags & (TH_URG)) ==0 &&  (tcp->th_flags & (TH_ACK)) ==0 )
					{
						c2ssyn++;
						c2s_syn_set = 1;  //SYN set so connection started
						countseq[ctos_total]=ntohs(tcp->th_seq);
					}
				}
				if((tcp->th_flags & TH_FIN)!=0)
				{
					if( (tcp->th_flags & (TH_SYN)) ==0 && (tcp->th_flags & (TH_PUSH)) ==0 && (tcp->th_flags & (TH_RST)) ==0 && (tcp->th_flags & (TH_URG)) ==0 &&  (tcp->th_flags & (TH_ACK)) ==0 )
					{
						c2sfin++;
					}
				}
			}
		if((tcp->th_flags & TH_PUSH)!=0)
		{
			c2spsh++;
			if( (tcp->th_flags & ( TH_ACK | TH_SYN | TH_FIN | TH_RST | TH_URG) )!=0 )
			{
				c2s_along_push++;
			}
			if( (tcp->th_flags & (TH_ACK) ) != 0 )
				{
				c2s_push_ack = 1;  push_count++;}

			if( (tcp->th_flags & (TH_SYN) ) != 0 )
				{
				c2s_push_syn = 1;  push_count++;}

			if( (tcp->th_flags & (TH_FIN) ) != 0 )
				{c2s_push_fin = 1;  push_count++;}

			if( (tcp->th_flags & (TH_RST) ) != 0 )
				{c2s_push_rst = 1;  push_count++;}

			if( (tcp->th_flags & (TH_URG) ) != 0 )
				{
				c2s_push_urg = 1;  push_count++;}
		}//10 and 22

		if((tcp->th_flags & TH_URG)!=0)
		{
			c2surg++;
			if( (tcp->th_flags & ( TH_ACK | TH_SYN | TH_FIN | TH_RST | TH_PUSH) )!=0 )
			{
				c2s_along_urg++;
			}
			if( (tcp->th_flags & (TH_ACK) ) != 0 )
				{
				c2s_urg_ack = 1;  }

			if( (tcp->th_flags & (TH_SYN) ) != 0 )
				{
				c2s_urg_syn = 1;  }

			if( (tcp->th_flags & (TH_FIN) ) != 0 )
				{c2s_urg_fin = 1;}

			if( (tcp->th_flags & (TH_RST) ) != 0 )
				{c2s_urg_rst = 1; }

			if( (tcp->th_flags & (TH_PUSH) ) != 0 )
				{
				c2s_urg_push = 1; }
		}
		if((tcp->th_flags & TH_RST)!=0)
		{
			c2srst++;
		}


		//printf("size of packet client to server %d is :%d\n",ctos_total+,header->len); //Size of packet is here
			sprintf(temp_pack_len,"%d",header->len);
		    ctos_pack_size.assign(temp_pack_len);
			ctos_uniq_pack_size[ctos_pack_size]++;



//*******************Sequence Number***********************//
	ctos_current_seq_number = ntohs(tcp->th_seq);
	if(packet_count == 1)
	{
		ctos_last_seq_number = ctos_current_seq_number ;
	}
	else
	{

		if(ctos_current_seq_number>ctos_last_seq_number)
		{
			ctos_wrap_count++;
			ctos_last_seq_number = ctos_current_seq_number ;
		}
		else
		{
			ctos_last_seq_number = ctos_current_seq_number ;
		}
		/*
		difference = ctos_current_seq_number - ctos_last_seq_number ;
		if(difference > 32768 )
		{
			ctos_wrap_count++;
			ctos_last_seq_number = ctos_current_seq_number ;
		}
		else if(difference< -32768 )
		{
			ctos_wrap_count++;
			ctos_last_seq_number = ctos_current_seq_number ;
		}
		else
		{
			ctos_last_seq_number = ctos_current_seq_number ;
		}
		difference = 0;
		*/
	}
	//printf("\nACK number: %d", ntohs(tcp->th_ack) );
	//printf("\nSeq Number: %d", ctos_current_seq_number);

	//******** Window close count ****//
	sprintf(temp_pack_len,"%d",ntohs(tcp->th_win));
	ctos_adv_size.assign(temp_pack_len);
	ctos_uniq_adv_size[ctos_adv_size]++;



	if(tcp->th_win == 0)
		ctos_nos_win_closed++;
	if(c2s_syn_set == 0)   //SYN flag has not encountered so initialize all the variables to zero.
	{
		initialize_ctos();
	}

}
	if(ntohs(tcp->th_sport) <1024 && ntohs(tcp->th_dport) > 1023) //****   Server to C  *********************************
	{
		stoc_total++;
			if( (tcp->th_flags & (TH_ACK))!=0 && (tcp->th_flags & (TH_SYN) )!=0    )
			{
				if( (tcp->th_flags & (TH_FIN)) ==0 && (tcp->th_flags & (TH_PUSH)) ==0 && (tcp->th_flags & (TH_RST)) ==0 && (tcp->th_flags & (TH_URG)) ==0 )
				{
					s2c_syn_ack++;
					s2c_syn_set = 1;  //SYN set so connection started;
				}
			}
			else if( (tcp->th_flags & (TH_FIN))!=0 && (tcp->th_flags & (TH_ACK))!=0 )
			{
				if( (tcp->th_flags & (TH_PUSH)) ==0 && (tcp->th_flags & (TH_URG)) ==0 && (tcp->th_flags & (TH_RST)) ==0 && (tcp->th_flags & (TH_SYN)) ==0 )
				{
					if(s2c_syn_set == 1)
					{
						s2c_fin_ack++;
						printf("\n\t Current Sequence Number: %u ", ntohl(tcp->th_seq) );
						print_stoc();
						initialize_stoc();
						s2c_syn_set = 0;    //Connection terminated so SYN set has been set to zero.!
					}
				}
			}
			else
			{
				if((tcp->th_flags & TH_ACK)!=0)
				{
					if( (tcp->th_flags & (TH_FIN)) ==0 && (tcp->th_flags & (TH_PUSH)) ==0 && (tcp->th_flags & (TH_RST)) ==0 && (tcp->th_flags & (TH_URG)) ==0 &&  (tcp->th_flags & (TH_SYN)) ==0 )
					{
					s2cack++;
				}
				}
				if((tcp->th_flags & TH_SYN)!=0)
				{
					if( (tcp->th_flags & (TH_FIN)) ==0 && (tcp->th_flags & (TH_PUSH)) ==0 && (tcp->th_flags & (TH_RST)) ==0 && (tcp->th_flags & (TH_URG)) ==0 &&  (tcp->th_flags & (TH_ACK)) ==0 )
					{
					s2csyn++;
					countseq[stoc_total]=ntohs(tcp->th_seq);
				}
				}
				if((tcp->th_flags & TH_FIN)!=0)
				{
					if( (tcp->th_flags & (TH_SYN)) ==0 && (tcp->th_flags & (TH_PUSH)) ==0 && (tcp->th_flags & (TH_RST)) ==0 && (tcp->th_flags & (TH_URG)) ==0 &&  (tcp->th_flags & (TH_ACK)) ==0 )
					{s2cfin++;
				}
				}
			}

		if((tcp->th_flags & TH_PUSH)!=0)
		{
			s2cpsh++;
			if( (tcp->th_flags & ( TH_ACK | TH_SYN | TH_FIN | TH_RST | TH_URG) )!=0 )
			{
				s2c_along_push++;
			}
			if( (tcp->th_flags & (TH_ACK) ) != 0 )
				{
				s2c_push_ack = 1;  push_count++;}

			if( (tcp->th_flags & (TH_SYN) ) != 0 )
				{
				s2c_push_syn = 1;  push_count++;}

			if( (tcp->th_flags & (TH_FIN) ) != 0 )
				{s2c_push_fin = 1;  push_count++;}

			if( (tcp->th_flags & (TH_RST) ) != 0 )
				{s2c_push_rst = 1;  push_count++;}

			if( (tcp->th_flags & (TH_URG) ) != 0 )
				{
				s2c_push_urg = 1;  push_count++;}
		}//10 and 22

		if((tcp->th_flags & TH_URG)!=0)
		{
			s2curg++;
			if( (tcp->th_flags & ( TH_ACK | TH_SYN | TH_FIN | TH_RST | TH_PUSH) )!=0 )
			{
				s2c_along_urg++;
			}
			if( (tcp->th_flags & (TH_ACK) ) != 0 )
				{
				s2c_urg_ack = 1;  }

			if( (tcp->th_flags & (TH_SYN) ) != 0 )
				{
				s2c_urg_syn = 1;  }

			if( (tcp->th_flags & (TH_FIN) ) != 0 )
				{s2c_urg_fin = 1;}

			if( (tcp->th_flags & (TH_RST) ) != 0 )
				{s2c_urg_rst = 1; }

			if( (tcp->th_flags & (TH_PUSH) ) != 0 )
				{
				s2c_urg_push = 1; }
		}
		if((tcp->th_flags & TH_RST)!=0)
		{
			s2crst++;
		}
		//printf("size of packet server to client %d is :%d\n",stoc_total,header->len); //Size of packet is here
		sprintf(temp_pack_len,"%d",header->len);
		stoc_pack_size.assign(temp_pack_len);
		stoc_uniq_pack_size[stoc_pack_size]++;

		stoc_current_seq_number = ntohs(tcp->th_seq);
		if(packet_count == 1)
		{
			stoc_last_seq_number = stoc_current_seq_number ;
		}
		else
		{
			if(stoc_current_seq_number>stoc_last_seq_number)
			{
				stoc_wrap_count++;
				stoc_last_seq_number = stoc_current_seq_number ;
			}
			else
			{
				stoc_last_seq_number = stoc_current_seq_number ;
			}

			/*
			difference = stoc_current_seq_number - stoc_last_seq_number ;

			if(difference > 32768 )
			{
				stoc_wrap_count++;
				stoc_last_seq_number = stoc_current_seq_number ;
			}
			else if(difference< -32768 )
			{
				stoc_wrap_count++;
				stoc_last_seq_number = stoc_current_seq_number ;
			}
			else
			{
				stoc_last_seq_number = stoc_current_seq_number ;
			}
			difference =0;
			*/
		}


if(s2c_syn_set == 0)   //SYN flag has not encountered so initialize all the variables to zero.
	{
		initialize_stoc();
	}

	}
	//printf("%d",count);

}//end of tcp packet condition


}



//***************************Main *************************
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


	//for(i=1;i<=ctos_total;i++)
			//printf("seq: %u\n",countseq[i]);       //Printing Sequence number here  *****************
	//print_ctos();
	//print_stoc();
	//initialize_ctos();
//print_ctos();

}


















