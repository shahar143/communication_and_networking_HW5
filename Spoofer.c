/*
	Raw TCP packets
*/
#include <stdio.h>	//for printf
#include <string.h> //memset
#include <sys/socket.h>	//for socket ofcourse
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <arpa/inet.h> // inet_addr
#include <unistd.h> // sleep()
#include <netinet/ip_icmp.h>	//Provides declarations for tcp header
#include <netinet/udp.h>	//Provides declarations for tcp header
#include <net/ethernet.h>
#include <time.h>


// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short *paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}

unsigned short in_cksum(unsigned short *addr, int len)

{

    int nleft = len;

    int sum = 0;

    unsigned short *w = addr;

    unsigned short answer = 0;

    while (nleft > 1) {

        sum += *w++;

        nleft -= 2;

    }

    if (nleft == 1) {

        *(unsigned char *) (&answer) = *(unsigned char *) w;

        sum += answer;

    }

    sum = (sum >> 16) + (sum & 0xFFFF);

    sum += (sum >> 16);

    answer = ~sum;

    return (answer);

}

// IP Header
struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
                       iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
                       iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
    unsigned short int iph_id;
    unsigned short iph_sum;
};

// ICMP Header

struct icmpheader {
    unsigned char       icmp_type; // ICMP message type
    unsigned char       icmp_code; // Error code
    unsigned short int  icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int  icmpid;     //Used for identifying request
    unsigned short int  icmpseq;    //Sequence number
    u_int16_t           icmp_ulen;            /* icmp length */

};

// UDP Header
struct udpheader
{
    u_int16_t udp_sport;           /* source port */
    u_int16_t udp_dport;           /* destination port */
    u_int16_t udp_ulen;            /* udp length */
    u_int16_t udp_sum;             /* udp checksum */
};

// TCP Header

struct tcpHeader {
    unsigned short int srcport;     //source port
    unsigned short int destport;    //destination port
    unsigned int seqnum;            //sequence number
//    unsigned int acknum;
    uint8_t th_flags;//acknowledgement number


    unsigned char  offset:4,           //TCP data offset
                   reserved:4;         //reserved data
    unsigned char  flag_res1:4,        //Control flags
                   flag_hlen:4,        //length of tcp header in 32-bit words
                   flag_fin:1,         //finish flag
                   flag_syn:1,         //synchronize sequence number
                   flag_rst:1,         //reset flag
                   flag_psh:1,         //push flag to send data to application
                   flag_ack:1,         //acknowledgement number
                   flag_urg:1,         //urgent pointer
                   flag_res2:2;
    unsigned short int winSize;        //Window size
    unsigned short int chksum;         //TCP checksum
    unsigned short int urgptr;         //Urgent pointer
    unsigned short int doff;

};

struct our_tcp_header
{
    uint32_t unix_time_stamp;
    uint16_t length;
    uint16_t reserved:3,
             c_flag:1,
             s_flag:1,
             t_flag:1,
             status:10;
    uint16_t cache;
    uint16_t padding;
};

// ETHERNET header
struct ethheader {
    u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
};

void send_raw_ip_packet(struct ipheader* ip);
void  Fill_Ip_Header(struct ipheader *ip, int WhichProtocol);
void Fill_Icmp_Header(char *buffer,int ipheaderlen);
void Fill_Udp_Header(char *buffer, int ipheaderlen);
void Fill_Tcp_Header(char *buffer, int ipheaderlen);


int main (int args, char* argv[])
{

    if (args != 3){
        printf("Usage: %s <srcIP> <victimIP>\n", argv[0]);
        exit(-1);
    }
    else{
    
        //Datagram to represent the packet
        char buffer[1500];

        memset(buffer,0,1500);

        /*********************************************************
             Step 2: Fill in the IP header.
         ********************************************************/

        int WhichProtocol;
        printf("To begin spoofer , choose the protocol you want to work with ,from the menu:-\n");
        printf("Press 1 to Protocol ICMP\n");
        printf("Press 2 to Protocol UDP\n");
        printf("Press 3 to Protocol TCP\n");

        scanf("%d",&WhichProtocol);
        printf("\n");
        char *protocols[] = {"ICMP","UDP","TCP"};
        printf("Well spoofer packets with protocol:-\t %s \n",protocols[WhichProtocol-1]);

        struct ipheader *ip = (struct ipheader *) (buffer + sizeof(struct ethheader));

        ip->iph_tos = 0x0;
        ip->iph_ver = 4; // meaning Ipv4
        ip->iph_ihl = 5; // The length if the ip header is 20 bytes/4 = 5
        ip->iph_ttl = 64; // Time to live
        // The ip address of dist and rec it would be any Ip Address,
        // Actually not my correct address.
        ip->iph_sourceip.s_addr = inet_addr(argv[1]);
        ip->iph_destip.s_addr = inet_addr(argv[2]);
        // the total length for our packet
        ip->iph_chksum =calculate_checksum((unsigned short *)&ip, 16);
        ip->iph_id = 0;
        ip->iph_len =  htons(sizeof(struct ipheader) + sizeof(struct ethheader));
        ip->iph_offset = 0x0;
        ip->iph_sum= in_cksum((unsigned short *)&ip, sizeof(ip));

        Fill_Ip_Header(ip,WhichProtocol);

        int ipheaderlen = ip->iph_ihl*4;


        // ICMP HEADER
        if (WhichProtocol==1){

            Fill_Icmp_Header(buffer,ipheaderlen);

        }
        // TCP HEADER
        else if (WhichProtocol != 2) {
            Fill_Tcp_Header(buffer, ipheaderlen);

        }
        // UDP HEADER
        else {
            Fill_Udp_Header(buffer,  ipheaderlen);

        }

        /*********************************************************
           Step 3: Finally, send the spoofed packet
         ********************************************************/

        send_raw_ip_packet(ip);
    }

    return 0;
}


void  Fill_Tcp_Header(char *buffer, int ipheaderlen) {

    struct tcpHeader *tcp =(struct tcpHeader*)(buffer + sizeof(struct ethheader) +ipheaderlen);

    char *data = buffer + sizeof(struct ipheader) + sizeof(struct tcpHeader);
    const char *msg = "Hello Client you are spoofing an tcp packet!\n";
    int data_len = strlen(msg);
    strncpy (data, msg, data_len);

    srand((unsigned int)2); // seed random number generator


    /* Hardcoded values */
    tcp->offset = 5;
    tcp->flag_ack = 0; // ack sequence should be 0
    tcp->flag_rst = 0;
    tcp->flag_fin = 0;
    tcp->flag_psh = 0;
    tcp->doff = 5; // set data offset
    /* Increase values by random value above 64 */
    tcp->seqnum = htonl(rand() % 65001); // generate random sequence number

    tcp->winSize = htons(rand() % 65536); // set window size
    tcp->th_flags = TH_SYN;
    /* User-defined values */
    tcp->srcport = htons(5335); // source port
    tcp->destport = htons(4568);  // destination port
    tcp->flag_hlen = htons(tcp->doff*4);
    if (tcp->urgptr == 1) tcp->urgptr = 1;
    else tcp->urgptr = 0;
    tcp->chksum = calculate_checksum((unsigned short *)&buffer, 16);


}


void Fill_Icmp_Header(char *buffer, int ipheaderlen) {


    struct icmpheader *icmp = (struct icmpheader *)  (buffer + sizeof(struct ethheader) + ipheaderlen);

    char *data = buffer + sizeof(struct ipheader) + sizeof(struct icmpheader);
    char *msg = "Hello Client you are spoofing an icmp packet!\n";
    int data_len = strlen(msg);
    strncpy (data, msg, data_len);


    icmp->icmp_type = ICMP_ECHO; //ICMP Type: 8 is request, 0 is reply.
    //  checksum if icmp header

    icmp->icmp_chksum = 0x3aa6; //calculate_checksum((unsigned short *)&buffer, 16);
    icmp->icmp_code = 0;
    icmp->icmpid = htons(40152);
    icmp->icmpseq = htons(5645);
    icmp->icmp_ulen =  htons(sizeof(struct icmpheader) + data_len);


}

void  Fill_Ip_Header(struct ipheader *ip,int WhichProtocol) {

    switch (WhichProtocol) {
        case 1:
            ip->iph_protocol = IPPROTO_ICMP;
            break;
        case 2:
            ip->iph_protocol = IPPROTO_UDP;
            ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct udpheader));
            break;
        case 3:
            ip->iph_protocol = IPPROTO_TCP;
            break;
        default:
            printf("Other Protocol\n");
    }
}





void Fill_Udp_Header( char *buffer, int ipheaderlen){

    /*********************************************************
       Step 1: Fill in the UDP data field.
     ********************************************************/

    struct udpheader *udp = (struct udpheader *) (buffer  + sizeof(struct ethheader) +ipheaderlen);

    char *data = buffer + sizeof(struct ipheader) +
                 sizeof(struct udpheader);
    const char *msg = "Hello Client you are spoofing an udp packet!\n";
    int data_len = strlen(msg);
    // bzero(msg, data_len);
    strncpy (data, msg, data_len);

    /*********************************************************
       Step 2: Fill in the UDP header.
     ********************************************************/
    udp->udp_sport = htons(12345);
    udp->udp_dport = htons(9090);
    udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
    udp->udp_sum =  0; /* Many OSes ignore this field, so we do not
                         calculate it. */
}


////  Given an IP packet, send it out using a raw socket.
////**************************************************************/
void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, ip->iph_protocol);
    if (sock<0){
        printf("***");
        perror("raw_socket");
    }

    // Step 2: Set socket option.
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
                  &enable, sizeof(enable))<0){
        perror("setsockopt");
        exit(-1);
    }

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;



    // Step 4: Send the packet out.

    while (1) {
        if (sendto(sock, ip, 1500, 0,
                   (struct sockaddr *) &dest_info, sizeof(dest_info)) < 0) {
            perror("sendto failed");
        }
            //Data send successfully
        else {
            printf("Packet Send. Length : %hu \n", ntohs(ip->iph_len));
        }
        // sleep for 1 seconds
        sleep(1);

    }
    close(sock);
}
