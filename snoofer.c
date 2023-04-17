//
// Created by codebind on 1/16/23.
//
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include<string.h>
#include<netinet/ip_icmp.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>
#include <pcap/pcap.h>

#define SIZE_ETH_HEADER 14


unsigned short in_cksum(unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }


    if (nleft == 1)
    {
        *(u_char *)(&temp) = *(u_char *)w;
        sum += temp;
    }


    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}


// ip header

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
};




/* ICMP Header  */
  struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int id;     //Used for identifying request
  unsigned short int seq;   //Sequence number
};
///* Ethernet header */
struct ethheader {
    u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
};




void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
void send_raw_ip_packet_snoofer(struct ipheader* ip);



struct sockaddr_in source,dest;
int tcp=0,udp=0, icmp_counter=0,others=0,igmp=0,total=0,i,j;



int main(){

    printf("//////////////////////////////////////////////////////////////\n");
    printf("                                                              \n");
    printf("  thank you for choosing snoppi the snoofer! :)               \n");
    printf("              ......                                          \n");
    printf("           :^^::::::^^:.......                                \n");
    printf("         ~:             .:::::::^:                            \n");
    printf("        7~         .77.           :~:.                        \n");
    printf("       :~ .YY.     .77.            ^GYJ                       \n");
    printf("      .!:YYYY?~^                   ~PP7                       \n");
    printf("      :~Y####Y~^                .^^                           \n");
    printf("       !:Y###Y:!          ..:^^::                             \n");
    printf("       .^^YYYY~^^^    ..:~^:.                                 \n");
    printf("          .....");
    printf("\033[1;31m"                                                      ); //set the next print to red
    printf("  !YJJJ77\n");
    printf("\033[0m"                                                         ); //set the next print to default color
    printf("                  ^~ ^  .~:                                   \n");
    printf("                  ?7 ~:   ^^                                  \n");
    printf("                 ^P! .!    ~:                                 \n");
    printf("              :. !?^..!    ~:                                 \n");
    printf("              ^!~~?~!~:. :^:                                  \n");
    printf("                  !  !:^!                                     \n");
    printf("                 .!  ~:^~!^^!^                                \n");
    printf("                .!.    ~:^7~!7:                               \n");
    printf("                .::::::^~:~:..                                \n");
    printf("                                                              \n");
    printf("                                                              \n");
    printf("//////////////////////////////////////////////////////////////\n");

    pcap_t *handle; // Session handle.
    char device[] = "br-69386c74bdc9"; // Device to sniff on.
    char errbuf[PCAP_ERRBUF_SIZE]; // Error string.
    struct bpf_program fp; // The compiled filter expression.
    char filter_exp[] = "icmp"; // the filter expression.
    bpf_u_int32 net = 0; // The IP of our sniffing device.


    // Step 1: Open live pcap session
    handle = pcap_open_live(device, 65536, 1, 1000, errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s :\n", errbuf);
        return(2);
    }

	int pcap = pcap_compile(handle, &fp, filter_exp, 0, net);
	  if(pcap < 0){
	    perror("pcap_compile");

	    exit(1);
	  }  

	pcap_setfilter(handle, &fp);
        pcap_loop(handle, -1, got_packet, NULL);


    /*
     cleanup
    */
    
    pcap_close(handle);   //Close the handle


    return 0;
}




void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {
    char buffersend[1500];

    //Get the IP Header part of this packet , excluding the ethernet header
    struct ipheader *iph = (struct ipheader *) (buffer + SIZE_ETH_HEADER);
    ++total;

    struct icmpheader *icmp = (struct icmpheader *) (buffer + SIZE_ETH_HEADER + sizeof(struct ipheader));

    if (icmp->icmp_type == 8) {
        icmp_counter++;
        memset(buffersend, 0, 1500);

        struct ipheader *iph_spoofer = (struct ipheader *) (buffersend + SIZE_ETH_HEADER);
        struct icmpheader *icmp_spoofer = (struct icmpheader *) (buffersend + SIZE_ETH_HEADER +
                                                                 sizeof(struct ipheader));

        iph_spoofer->iph_ver = 4;
        iph_spoofer->iph_ihl = 5;
        iph_spoofer->iph_ttl = 20;

        iph_spoofer->iph_sourceip = iph->iph_destip;
        iph_spoofer->iph_destip = iph->iph_sourceip;

        iph_spoofer->iph_protocol = IPPROTO_ICMP;
        iph_spoofer->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

        icmp_spoofer->icmp_type = 0;
        icmp_spoofer->icmp_chksum = 0;
        icmp_spoofer->icmp_chksum = in_cksum((unsigned short *) icmp_spoofer, sizeof(struct icmpheader));


        printf("Spoof done\n");
        printf("source_ip: %s", inet_ntoa(iph_spoofer->iph_sourceip));
        printf(", dest_ip: %s\n", inet_ntoa(iph_spoofer->iph_destip));


        send_raw_ip_packet_snoofer(iph_spoofer);


    
    }
}

    void send_raw_ip_packet_snoofer(struct ipheader *ip) {

        struct sockaddr_in dest_info;

        int enable = 1;

        // Step 1: Create a raw network socket.
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) {
            perror("raw_socket");
        }

        // Step 2: Set socket option.
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
                       &enable, sizeof(enable)) < 0) {
            perror("srtsockopt");
            return;
        }

        // Step 3: Provide needed information about destination.
        
        dest_info.sin_family = AF_INET;
        dest_info.sin_addr = ip->iph_destip;


        // Step 4: Send the packet out.

        if (sendto(sock, ip, ntohs(ip->iph_len), 0,
                   (struct sockaddr *) &dest_info, sizeof(dest_info)) < 0) {
            perror("sendto failed");
        }
        

        close(sock);
    }

