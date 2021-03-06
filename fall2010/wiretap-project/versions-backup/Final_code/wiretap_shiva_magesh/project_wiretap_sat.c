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
long int ethtype[1000];
unsigned int proto[1000];
static int badcheck;   //For check sum
static int corcheck;
static int omicheck;

FILE *ip_des_list, *ip_src_list, *eth_src_list, *eth_des_list, *proto_list;
FILE *tcp_port_src_list, *tcp_port_des_list, *udp_port_src_list, *udp_port_des_list;

struct _ip_count
{
	char ip[30];
	int count;
}ip_count[1000];

struct _ip_list
{
	char ip[30];
	int check;
}ip_list[1000];

/***********************Padding function**************************************/
char *RightPad(char *string, int pad_len, char *pad_char) {
    int len = (int) strlen(string);
    if (len >= pad_len) {
        return string;
    }
    int i;
    for (i = 0; i < pad_len - len; i++) {
        strcat(string, pad_char);
    }
    return string;
}

/*******Check sum****************************
inputs: UDP length, IP src addr, IP destination addr
returns: check sum
********************************************/
unsigned checksum(const void *buffer,size_t len,struct in_addr src_addr,struct in_addr dest_addr)
{
 		const uint16_t *buf=buffer;
                uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
              uint32_t sum;
             size_t length=len;


              sum = 0;
              while (len > 1)
              {

                 sum += *buf++;
                      if (sum & 0x80000000)
                              sum = (sum & 0xFFFF) + (sum >> 16);
                      len -= 2;
              }

              if ( len & 1 )

                      sum += *((uint8_t *)buf);


         sum += *(ip_src++);
              sum += *ip_src;

              sum += *(ip_dst++);
              sum += *ip_dst;

              sum += htons(IPPROTO_UDP);
              sum += htons(length);


              while (sum >> 16)
                      sum = (sum & 0xFFFF) + (sum >> 16);


              return ( (uint16_t)(~sum)  );
}
/***********************************/

/****************************************************
inputs needed : Handle of the file containing all the addresses
returns nothing
Prints Count of Unique addresses
**************************************************/
PrintIpCount(FILE *ip_read)
{

	int len;
	char iptemp[30], ip_check[30];
	int k, j,ipCount=0, maxc=0,ipMaxCount=0;

	for(k=0;k< count ; k++)
	{
		fgets(iptemp , 20,ip_read);
		len = strlen(iptemp);
		if(iptemp[len-1]=='\n')
			iptemp[len-1]='\0';
		strcpy(ip_list[k].ip, iptemp);
		maxc++;
		if(feof(ip_read))
			break;
	}

	int tempCount;
	int iCopyTemp=0;
	char *p;
	for(k=0;k<maxc;k++)    //outer loop
	{
		if(strcmp(ip_list[k].ip,"done") != 0)
		{
			strcpy(ip_check , ip_list[k].ip);
			for(j= 0, tempCount=0; j<maxc; j++,tempCount++)  //inner loop
			{
				if(strcmp(ip_check, ip_list[tempCount].ip) == 0 )
				{
					iCopyTemp++;
					strcpy(ip_list[tempCount].ip,"done");
				}
			}//End of   j   loop

				strcpy(ip_count[ipCount].ip, ip_check);   // ip_count is a unique ip recorder structure
			 	ip_count[ipCount].count=iCopyTemp;
				ipCount++;
				ipMaxCount++;
				iCopyTemp = 0;
		}
	} //End of   k   loop

	for(k=0;k< ipMaxCount ; k++)
	{
		printf("   %s\t\t %d\n",RightPad( ip_count[k].ip, 20," "), ip_count[k].count);
	}
}

/*********************Packet Handler********************************/
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
	printf("\n\nStart time and date of the capture is: %s\n",ctime(&header->ts.tv_sec));
	start=header->ts.tv_sec;
	}
	end=header->ts.tv_sec;

	ip = (struct sniff_ip*)(pkt_data + 14);
	size_ip = IP_HL(ip)*4;
	if(size_ip==8 || size_ip==32|| size_ip==0)
	{
	size[count]=header->len;
	count++;
	return;
	}

	ethtype[p]=ntohs(ethernet->ether_type);
	p++;

	size[count]=header->len;
		//fprintf(stdout,"source: %s \n",ether_ntoa((struct ether_header*)ethernet->ether_shost));
	fprintf(eth_src_list, "%s\n",ether_ntoa((struct ether_header*)ethernet->ether_shost));   //Printing eth addrses into a file

    	//fprintf(stdout,"dest: %s \n",ether_ntoa((struct ether_header*)ethernet->ether_dhost));
    fprintf(eth_des_list, "%s\n",ether_ntoa((struct ether_header*)ethernet->ether_dhost));   //Printing eth addrses into a file

		//printf("ether type is:%.4x\n",ntohs((struct ether_header*)ethernet->ether_type));
	tcp = (struct sniff_tcp*)(pkt_data + 14 + size_ip);
	size_tcp = TH_OFF(tcp)*4;

	struct udphdr *udph = (struct udphdr*)(pkt_data + 14 + size_ip);

	if (size_ip==0)
	{

		ip = (struct sniff_ip*)(pkt_data + 12+14);
		//printf("   * Invalid IP header length: %u bytes\n", size_ip);
		//fprintf(stdout," prot %u \n ",ip->ip_p);


		ip = (struct sniff_ip*)(pkt_data + 12);

		count++;
		//printf("packet number is %d\n",count);

		return;
	}

	else
	{
		if(ip->ip_p==6)
		{

		//tsport[p]=ntohs(tcp->th_sport);
		//printf("   Src port: %d\n",tsport[p]);
			fprintf(tcp_port_src_list,"%d\n",ntohs(tcp->th_sport));   //Writing into a file
		//p++;
		//printf("   Dst port: %d\n", ntohs(tcp->th_dport));
			fprintf(tcp_port_des_list,"%d\n",ntohs(tcp->th_dport));    // Writing into a file

			if((tcp->th_flags & TH_ACK)!=0)
			{

			ack++;
			}
			if((tcp->th_flags & TH_RST)!=0)
			{

			rst++;
			}
			if((tcp->th_flags & TH_SYN)!=0)
			{
			syn++;
			}
			if((tcp->th_flags & TH_PUSH)!=0)
			{
			psh++;
			}
			if((tcp->th_flags & TH_FIN)!=0)
			{
			fin++;
			}
			if((tcp->th_flags & TH_URG)!=0)
			{
			urg++;
			}
			if((tcp->th_flags & TH_ECE)!=0)
			{
			ece++;
			}
			if((tcp->th_flags & TH_CWR)!=0)
			{
			cwr++;
			}
		}

		{/************ Writing Protocol type into File*************/
			if(ip->ip_p==6)
				fprintf(proto_list, "%s", "TCP");
			else if(ip->ip_p==17)
				fprintf(proto_list, "%s", "UDP");
			else
				fprintf(proto_list, "%s", "none");
		}
		if(ip->ip_p==17)
		{
		//printf("   Src port: %d\n", ntohs(udph->uh_sport));
			fprintf(udp_port_src_list,"%d\n",ntohs(udph->uh_sport));   //Writing into a file
		//printf("   Dst port: %d\n", ntohs(udph->uh_dport));
			fprintf(udp_port_des_list,"%d\n",ntohs(udph->uh_dport));   //Writing into a file

		//printf("   length %d\n",ntohs(udph->uh_ulen));
		}

	proto[p]=ip->ip_p;
	p1++;

	fprintf(ip_src_list, "%s\n", inet_ntoa(ip->ip_src));
	fprintf(ip_des_list, "%s\n", inet_ntoa(ip->ip_dst));
	count++;
	//printf("packet number is %d\n",count);

	}
	if(ip->ip_p==17)
		{
		bool check;

			uint16_t len = ntohs(udph->uh_ulen);
			if ( udph->uh_sum != 0 )
	         	{
	                 // The checksum is used                                 //
	                 if ( udph->uh_sum == 0xFFFF )
	                         udph->uh_sum = 0x0000;

	                // Calculate the checksum                               //
	                check = checksum(udph,ntohs(udph->uh_ulen),ip->ip_src,ip->ip_dst);
			if ( check )
	                	{
				badcheck++;
	                        //printf("\n\rUDP checksum error! %04X", check);
	                        return;
	                	}
			else
				{
				corcheck++;
				return;
				}
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


		ip_des_list = fopen("ipdes.txt","w");
		ip_src_list = fopen("ipsrc.txt","w");
		eth_src_list = fopen("ethsrc.txt","w");
		eth_des_list = fopen("ethdes.txt","w");
		proto_list = fopen("proto_list.txt","w");
		tcp_port_src_list = fopen("tcp_port_src.txt","w");
		tcp_port_des_list = fopen("tcp_port_des.txt","w");
		udp_port_src_list = fopen("udp_port_src.txt","w");
		udp_port_des_list = fopen("udp_port_des.txt","w");

		pcap_loop(handle, 0, packet_handler, NULL);
		pcap_close(handle);
		FILE *ip_des_read, *ip_src_read, *eth_src_read, *eth_des_read;
		FILE *tcp_port_src_read, *tcp_port_des_read, *udp_port_src_read, *udp_port_des_read;
		fclose(ip_des_list);
		fclose(ip_src_list);
		fclose(eth_src_list);
		fclose(eth_des_list);
		fclose(tcp_port_src_list);
		fclose(tcp_port_des_list);
		fclose(udp_port_src_list);
		fclose(udp_port_des_list);

	printf("\n  Ethernet Source     \t\tCount\n");
		eth_src_read = fopen("ethsrc.txt","r");
		PrintIpCount(eth_src_read);        //Calling the function to print Source Ethernet addresses count
		fclose(eth_src_read);

	printf("\n  Ethernet Destination     \tCount\n");
		eth_des_read = fopen("ethdes.txt","r");
		PrintIpCount(eth_des_read);        //Calling the function to print Destination Ethernet addresses count
		fclose(eth_des_read);


	printf("\n  Source IP address     \tCount\n");
		ip_src_read = fopen("ipsrc.txt","r");
		PrintIpCount(ip_src_read);    //Calling the function to print Source IP addresses count
		fclose(ip_src_read);

	printf("\n  Destination IP address     \tCount\n");
		ip_des_read = fopen("ipdes.txt","r");
		PrintIpCount(ip_des_read);        //Calling the function to print Destination IP addresses count
	fclose(ip_des_read);

	printf("\n  TCP Source Port Address     \tCount\n");
		tcp_port_src_read = fopen("tcp_port_src.txt","r");
		PrintIpCount(tcp_port_src_read);
		fclose(tcp_port_src_read);

	printf("\n  TCP Destination Port Address  Count\n");
		tcp_port_des_read = fopen("tcp_port_des.txt","r");
		PrintIpCount(tcp_port_des_read);
		fclose(tcp_port_des_read);

	printf("\n  UDP Source Port Address     \tCount\n");
		udp_port_src_read = fopen("udp_port_src.txt","r");
		PrintIpCount(udp_port_src_read);
		fclose(udp_port_src_read);

	printf("\n  UDP Destination Port Address  Count\n");
		udp_port_des_read = fopen("udp_port_des.txt","r");
		PrintIpCount(udp_port_des_read);
		fclose(udp_port_des_read);

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
		case IPPROTO_TCP:
		tcp++;
		break;
		case IPPROTO_UDP:
		udp++;
		break;
		}
	}
	printf("\ntransport protocol summary\n");
	printf("------------------------------\n");
	printf("1\t\t%d\n",count1);
	printf("2\t\t%d\n",count2);
	printf("tcp\t\t%d\n",tcp);
	printf("udp\t\t%d\n",udp);
	printf("\nnetwork protocol summary\n");
	printf("------------------------------\n");
	printf("protocol\t#packets\n");

	printf("26\t\t%d\n",count26);
	printf("52\t\t%d\n",count52);
	printf("62\t\t%d\n",count62);
	printf("806\t\t%d\n",count806);
	printf("ip\t\t%d\n",ip);


	printf("\nDuration is %ld\n",end-start);
	printf("Average packet size is  %0.2f\n",avg);
	printf("Minimum packet size is %d\n",min);
	printf("Maximum packet size is %d\n\n",max);

	omicheck=udp-(corcheck+badcheck);
	printf("the number of bad checksum is %d\n",badcheck++);
	printf("the number of correct checksum is %d\n",corcheck++);
	printf("the number of omitted checksum is %d\n",omicheck++);

	printf("Total Number of packets is %d\n\n",count);


	printf("Packets Flow Summary\n");
	{  /*******************Independent block*****************/
			int len;
			char iptemp[30], ip_check[30];
			int k, j,ipCount=0, srcmax=0, desmax=0 ,ipMaxCount=0, iFlowSum=0, iFound=0;
			FILE *ip_src_sum = fopen("ipsrc.txt","r");
			FILE *ip_des_sum = fopen("ipdes.txt","r");
			struct _ip_list ip_src[1000], ip_des[1000];
			struct _flow_sum
			{
				char protocol[10];
				char ip_src[30];
				char proto_src[30];
				char ip_des[30];
				char proto_des[30];
				int one_two;
				int two_one;
			}flow_sum[1000];

			for(k=0;k< count ; k++)
			{
				fgets(iptemp, 20,ip_src_sum);
				len = strlen(iptemp);
				if(iptemp[len-1]=='\n')
					iptemp[len-1]='\0';
				strcpy(ip_src[k].ip, iptemp);
				srcmax++;
				if(feof(ip_src_sum))
					break;
			}
			for(k=0;k< count ; k++)
			{
				fgets(iptemp, 20,ip_des_sum);
				len = strlen(iptemp);
				if(iptemp[len-1]=='\n')
					iptemp[len-1]='\0';
				strcpy(ip_des[k].ip, iptemp);
				desmax++;
				if(feof(ip_des_sum))
					break;
			}

			int tempCount;
			int iCopyTemp=0;
			char *p;
			char tempProtocol[10];

			for(k=0;k<srcmax;k++)    //outer loop
			{
				if(proto[k]==6||proto[k]==17)
				{
					if(proto[k]==6)
						strcpy(tempProtocol,"TCP");
					else
						strcpy(tempProtocol,"UDP");

					for(i=0; i<srcmax; i++)
					{
						if(strcmp(ip_src[k].ip,flow_sum[i].ip_src) == 0 && strcmp(ip_des[k].ip, flow_sum[i].ip_des)==0 )
						{
							flow_sum[i].one_two+=1;
							iFound = 1;
							break;
						}
					}
					if(iFound != 1)
					{
						strcpy(flow_sum[iFlowSum].ip_src,ip_src[k].ip);
						strcpy(flow_sum[iFlowSum].ip_des,ip_des[k].ip);
						strcpy(flow_sum[iFlowSum].protocol,tempProtocol);
						flow_sum[iFlowSum].one_two = 1;
						iFlowSum++;
					}
				}//End of Proto if statement
				iFound=0;   //Resetting the flag
			} //End of   k   loop
		printf(" Type\t\tIP1 \t\t     IP2 \t  #Packet 1-2  \t  #Packet 2-1\n");
		for(k=0;k< iFlowSum ; k++)
		{
				printf("  %s   %s  %s   %d\n",RightPad(flow_sum[k].protocol, 4," "), RightPad( flow_sum[k].ip_src, 20," "), RightPad( flow_sum[k].ip_des, 20," "), flow_sum[k].one_two);
		}

	}

	return 0;
}
