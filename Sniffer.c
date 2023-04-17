#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include<string.h> //for memset
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header


void print_tcp_packet(const u_char *  , int );
void print_udp_packet(const u_char * , int);
void print_icmp_packet(const u_char * , int );
void PrintData (const u_char * , int);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
int filter(pcap_t *handler, struct bpf_program *fp, char filter_exp[5], bpf_u_int32 net);

struct application_hdr
{
    uint32_t unix_time_stamp;
    uint16_t length;
    uint16_t reserved:3,
            c_flag:1,
            s_flag:1,
            t_flag:1,
            status:10;
    uint16_t cache_control;
    uint16_t padding;
};

FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0;


int main(int argc, char *argv[]){

    if(argc != 2){
        printf("Usage: %s <filter expression>\n", argv[0]);
        return 1;
    }
    else{
        pcap_t *handle; // Session handle.
        char device[] = "lo"; // Device to sniff on.
        char errbuf[PCAP_ERRBUF_SIZE]; // Error string.
        struct bpf_program fp; // The compiled filter expression.
        char filter_exp[5]; // the filter expression.

        bpf_u_int32 net; // The IP of our sniffing device.



        // Step 1: Open live pcap session on NIC with name lo
        handle = pcap_open_live(device, 65536, 1, 1000, errbuf);

        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open device %s :\n", errbuf);
            return(2);
        }

        if(strcmp(argv[1], "tcp") == 0){
            strcpy(filter_exp, "tcp");
        }
        else if(strcmp(argv[1], "udp") == 0){
            strcpy(filter_exp, "udp");
        }
        else if(strcmp(argv[1], "icmp") == 0){
            strcpy(filter_exp, "icmp");
        }
        else{
            printf("Usage: %s <filter expression>\n", argv[0]);
            return 1;
        }

        filter(handle, &fp, filter_exp, net);


        logfile = fopen("log.txt", "w");
        if(logfile==NULL)
        {
            printf("Unable to create file.");
        }

        fprintf(logfile , "IDs\n");
        fprintf(logfile , "208113381, 211990700\n\n");
        fprintf(logfile , "********************************************************\n\n");

        // Step 3: Capture packets
        /*
         Explain arguments of the below function (pcap_loop) :-

         int	pcap_loop(pcap_t *, int cnt, pcap_handler, u_char *user);
            1. The first argument is our session handle.

            2. the second argument is an integer that tell pcap_loop()
                 how many packets it should sniff for before returning.

            3. The third argument is the name of the callback function.
                 like in mycode the name of this function is get_packet.

            4. The last argument , actually in many times is simply set as NULL.
                  Suppose we have arguments of our own that we wish to send to out callback function,
                       in addition to the arguments that pcap_loop() sends.
          */

        pcap_loop(handle, -1, got_packet, NULL);


        /*
         cleanup
        */
        pcap_freecode(&fp);
        pcap_close(handle);   //Close the handle


        return 0;
    }
}

int filter(pcap_t *handle, struct bpf_program *fp, char filter_exp[5], bpf_u_int32 net) {

    // Step 2: Compile filter_exp into BPF psuedo-code
    if (pcap_compile(handle, fp, filter_exp, 0, net)==-1){
        printf("Couldn't parse filter %s: %s\n",filter_exp, pcap_geterr(handle));
        return(1);

    }


    if (pcap_setfilter(handle, fp)==-1){
        printf("Couldn't install filter %s: %s\n",filter_exp, pcap_geterr(handle));
        return(1);

    }

    return 0;

}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;

    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
            print_icmp_packet( buffer , size);
            break;

        case 2:  //IGMP Protocol
            ++igmp;
            break;

        case 6:  //TCP Protocol
            ++tcp;
            print_tcp_packet(buffer , size);
            break;

        case 17: //UDP Protocol
            ++udp;
            print_udp_packet(buffer , size);
            break;

        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}


void print_tcp_packet(const u_char * Packet, int Size)
{
    struct iphdr *iph = (struct iphdr *)( Packet  + sizeof(struct ethhdr) );
    unsigned short iphdrlen = iph->ihl*4;

    struct sockaddr_in source,dest;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    struct tcphdr *tcph=(struct tcphdr*)(Packet + iphdrlen + sizeof(struct ethhdr));
    unsigned short tcphdrlen = tcph->doff*4;

    char *a = (char*)(tcph+6*sizeof(char));
    int mask = 28;
    int b = (int)(*a) & mask;
    int c = b >> 2;
    int d = c & 1;
    int e = c >> 1;
    int f = e & 1;
    int g = e >> 1;
    int h = g & 1;

    int *x = (int*)(tcph+ 4*sizeof(char));
    mask = 1023;
    int status = *x & mask;

    fprintf(logfile , "critisizm!!: \n");
    fprintf(logfile , "   |-Cache Flag                : %d\n",d);
    fprintf(logfile , "   |-Steps Flag                : %d\n",f);
    fprintf(logfile , "   |-Type Flag                 : %d\n",h);
    fprintf(logfile , "   |-Status                    : %d\n",status);

    fprintf(logfile , "end of critisizm\n");

    struct application_hdr *our_apph = (struct application_hdr*)(Packet + iphdrlen + tcphdrlen + sizeof(struct ethhdr));
    unsigned short our_apphdrlen = sizeof(struct application_hdr);

    int header_size =  (int)sizeof(struct ethhdr) + iphdrlen + tcphdrlen + our_apphdrlen;


    fprintf(logfile , "\n\n***********************TCP Packet*************************\n");
    fprintf(logfile , "\nTCP Header\n");
    fprintf(logfile , "   |-Source Port               : %u\n",ntohs(tcph->source));
    fprintf(logfile , "   |-Destination Port          : %u\n",ntohs(tcph->dest));
    fprintf(logfile , "   |-Source IP                 : %s\n", inet_ntoa(source.sin_addr));
    fprintf(logfile , "   |-Destination IP            : %s\n", inet_ntoa(dest.sin_addr));
    fprintf(logfile , "   |-IP Header Length          : %d\n", ntohs(iph->tot_len));
    fprintf(logfile , "   |-TCP Header Length         : %d\n", tcphdrlen);
    fprintf(logfile , "   |-Total Length              : %d\n", our_apph->length);
    fprintf(logfile , "   |-Unix Time Stamp           : %u\n", our_apph->unix_time_stamp);
    fprintf(logfile , "   |-Cache Control             : %d\n",our_apph->cache_control);
    fprintf(logfile , "   |-Cache Flag                : %d\n",our_apph->c_flag);
    fprintf(logfile , "   |-Steps Flag                : %d\n",our_apph->s_flag);
    fprintf(logfile , "   |-Type Flag                 : %d\n",our_apph->t_flag);
    fprintf(logfile , "   |-Status                    : %d\n",our_apph->status);


    fprintf(logfile , "\n");
    fprintf(logfile , "                        DATA Dump                         ");
    fprintf(logfile , "\n");

    fprintf(logfile , "TCP Header\n");
    PrintData(Packet+iphdrlen,tcphdrlen);

    fprintf(logfile , "Data Payload\n");
    PrintData(Packet + header_size , Size - header_size );

    fprintf(logfile , "\n###########################################################\n");
}

void print_udp_packet(const u_char *Buffer , int Size){
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    struct sockaddr_in source,dest;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
    unsigned short udphdrlen = sizeof(struct udphdr);

    struct application_hdr *our_apph = (struct application_hdr*)(Buffer + iphdrlen + udphdrlen + sizeof(struct ethhdr));
    unsigned short our_apphdrlen = sizeof(struct application_hdr);

    int header_size =  sizeof(struct ethhdr) + iphdrlen + udphdrlen + our_apphdrlen;

    char *a1 = (char*)(udph+6*sizeof(char));
    int a = (int)*a1;
    int mask = 28;
    int b = a & mask;
    int c = b >> 2;
    int d = c & 1;
    int e = c >> 1;
    int f = e & 1;
    int g = e >> 1;
    int h = g & 1;

    int *x = (int*)(udph+ 4*sizeof(char));
    mask = 1023;
    int status = *x & mask;

    fprintf(logfile , "critisizm!!: \n");
    fprintf(logfile , "   |-Cache Flag                : %d\n",d);
    fprintf(logfile , "   |-Steps Flag                : %d\n",f);
    fprintf(logfile , "   |-Type Flag                 : %d\n",h);
    fprintf(logfile , "   |-Status                    : %d\n",status);

    fprintf(logfile , "end of critisizm\n");


    fprintf(logfile , "\n\n***********************UDP Packet*************************\n");


    fprintf(logfile , "\nUDP Header\n");
    fprintf(logfile , "   |-Source Port               : %d\n",ntohs(udph->source));
    fprintf(logfile , "   |-Destination Port          : %d\n",ntohs(udph->dest));
    fprintf(logfile , "   |-Source IP                 : %s\n",inet_ntoa(source.sin_addr) );
    fprintf(logfile , "   |-Destination IP            : %s\n",inet_ntoa(dest.sin_addr) );
    fprintf(logfile , "   |-IP Header Length          : %d\n",ntohs(iph->tot_len));
    fprintf(logfile , "   |-UDP Header Length         : %d\n",ntohs(udph->len));
    fprintf(logfile , "   |-Total Length              : %d\n", our_apph->length);
    fprintf(logfile , "   |-Unix Time Stamp           : %u\n",our_apph->unix_time_stamp);
    fprintf(logfile , "   |-Cache Control             : %d\n",our_apph->cache_control);
    fprintf(logfile , "   |-Cache Flag                : %d\n",our_apph->c_flag);
    fprintf(logfile , "   |-Steps Flag                : %d\n",our_apph->s_flag);
    fprintf(logfile , "   |-Type Flag                 : %d\n",our_apph->t_flag);
    fprintf(logfile , "   |-Status                    : %d\n",our_apph->status);


    fprintf(logfile , "\n");
    fprintf(logfile , "UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);

    fprintf(logfile , "Data Payload\n");

    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , Size - header_size);

    fprintf(logfile , "\n###########################################################");
}

void print_icmp_packet(const u_char *Packet , int Size)
{
    struct iphdr *iph = (struct iphdr *)(Packet  + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;

    struct sockaddr_in source,dest;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    struct icmphdr *icmph = (struct icmphdr *)(Packet + sizeof(struct ethhdr) + iphdrlen);

    struct application_hdr *our_apph = (struct application_hdr*)(Packet + sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr));
    unsigned short our_apphdrlen = sizeof(struct application_hdr);

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(struct icmphdr) + our_apphdrlen;

    char *a1 = (char*)(icmph+6*sizeof(char));
    int a = (int)*a1;
    int mask = 28;
    int b = a & mask;
    int c = b >> 2;
    int d = c & 1;
    int e = c >> 1;
    int f = e & 1;
    int g = e >> 1;
    int h = g & 1;

    int *x = (int*)(icmph+ 4*sizeof(char));
    mask = 1023;
    int status = *x & mask;

    fprintf(logfile , "critisizm!!: \n");
    fprintf(logfile , "   |-Cache Flag                : %d\n",d);
    fprintf(logfile , "   |-Steps Flag                : %d\n",f);
    fprintf(logfile , "   |-Type Flag                 : %d\n",h);
    fprintf(logfile , "   |-Status                    : %d\n",status);

    fprintf(logfile , "end of critisizm\n");


    fprintf(logfile , "\n");
    fprintf(logfile , "ICMP Header\n");
    fprintf(logfile , "   |-Type                      : %d\n",(unsigned int)(icmph->type));
    fprintf(logfile , "   |-Source IP                 : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile , "   |-Destination IP            : %s\n",inet_ntoa(dest.sin_addr));
    fprintf(logfile , "   |-IP Total Length           : %d\n",ntohs(iph->tot_len));
    fprintf(logfile , "   |-Total Length              : %d\n", our_apph->length);
    fprintf(logfile , "   |-Unix Time Stamp           : %u\n",our_apph->unix_time_stamp);
    fprintf(logfile , "   |-Cache Control             : %d\n",our_apph->cache_control);
    fprintf(logfile , "   |-Cache Flag                : %d\n",our_apph->c_flag);
    fprintf(logfile , "   |-Steps Flag                : %d\n",our_apph->s_flag);
    fprintf(logfile , "   |-Type Flag                 : %d\n",our_apph->t_flag);
    fprintf(logfile , "   |-Status                    : %d\n",our_apph->status);


    if((unsigned int)(icmph->type) == 11){
        fprintf(logfile , "  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY){
        fprintf(logfile , "  (ICMP Echo Reply)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHO){
        fprintf(logfile , "  (ICMP Echo Request)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_DEST_UNREACH){
        fprintf(logfile , "  (Destination Unreachable)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_REDIRECT){
        fprintf(logfile , "  (Redirect)\n");
    }
    else{
        fprintf(logfile , "  (Unknown)\n");
    }

    fprintf(logfile , "\n");


    fprintf(logfile , "ICMP Header\n");
    PrintData(Packet + iphdrlen + sizeof(struct ethhdr) , sizeof icmph);

    fprintf(logfile , "Data Payload\n");

    //Move the pointer ahead and reduce the size of string
    PrintData(Packet + header_size , (Size - header_size) );

    fprintf(logfile , "\n###########################################################");
}

void PrintData (const u_char * data , int Size)
{
    int i , j;
    for(i = 0 ; i < Size ; i++){
        if(i != 0 && i % 16==0){  //if one line of hex printing is complete...
            fprintf(logfile , "         ");
            for( j= i-16 ; j < i ; j++){
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
                else{
                    fprintf(logfile , "."); //otherwise print a dot
                }
            }
            fprintf(logfile , "\n");
        }

        if(i%16==0) fprintf(logfile , "   ");
        fprintf(logfile , " %02X",(unsigned int)data[i]);
        if(i == Size-1)  //print the last spaces
        {
            for(j = 0; j < 15 - i % 16; j++){
                fprintf(logfile , "   "); //extra spaces
            }
            fprintf(logfile , "         ");
            for(j = i - i % 16 ;j <= i; j++){
                if(data[j] >= 32 && data[j] <= 128){
                    fprintf(logfile , "%c",(unsigned char)data[j]);
                }
                else{
                    fprintf(logfile , ".");
                }
            }
            fprintf(logfile ,  "\n" );
        }
    }
}