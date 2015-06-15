#include <pcap.h> 
#include <string.h> 
#include <stdlib.h> 
#include <ctype.h>
#include <arpa/inet.h>


// add color from here
// http://stackoverflow.com/questions/3585846/color-text-in-terminal-aplications-in-unix

#define MAXBYTES2CAPTURE 2048 

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

// char filter_exp[] = "port 80";  /* The filter expression */
char filter_exp[] = "";  /* The filter expression */
struct bpf_program fp;    /* The compiled filter expression */
bpf_u_int32 mask;   /* The netmask of our sniffing device */
bpf_u_int32 net;   /* The IP of our sniffing device */


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

void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet){ 

 int i=0, *counter = (int *)arg; 

 /* declare pointers to packet headers */
 const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
 const struct sniff_ip *ip;              /* The IP header */
 const struct sniff_tcp *tcp;            /* The TCP header */
 const char *payload;                    /* Packet payload */
 int size_ip;
 int size_tcp;
 int size_payload;
 
 printf("###########################################################\n");
 printf("Packet Count: %d\n", ++(*counter)); 
 printf("Received Packet Size: %d\n", pkthdr->len); 
 printf("Caplen: %u\n", pkthdr->caplen);
 /* define ethernet header */
 ethernet = (struct sniff_ethernet*)(packet);
 
 /* define/compute ip header offset */
 ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
 size_ip = IP_HL(ip)*4;
 if (size_ip < 20) {
         printf("   * Invalid IP header length: %u bytes\n", size_ip);
         return;
 }

 /* print source and destination IP addresses */
 printf("From: %s\n", inet_ntoa(ip->ip_src));
 printf("To: %s\n", inet_ntoa(ip->ip_dst));

 /* determine protocol */       
 switch(ip->ip_p) {
   case IPPROTO_TCP:
           printf("Protocol: TCP\n");
           break;
   case IPPROTO_UDP:
           printf("Protocol: UDP\n");
           printf("-----------------------------------------------------------\n\n");
           return;
   case IPPROTO_ICMP:
           printf("Protocol: ICMP\n");
           printf("-----------------------------------------------------------\n\n");
           return;
   case IPPROTO_IP:
           printf("Protocol: IP\n");
           printf("-----------------------------------------------------------\n\n");
           return;
   default:
           printf("Protocol: unknown\n");
           printf("-----------------------------------------------------------\n\n");
           return;
 }
 
 /*
  *  OK, this packet is TCP.
  */
 
 /* define/compute tcp header offset */
 tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
 size_tcp = TH_OFF(tcp)*4;
 if (size_tcp < 20) {
         printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
         return;
 }
 
 printf("Src port: %d\n", ntohs(tcp->th_sport));
 printf("Dst port: %d\n", ntohs(tcp->th_dport));
         

 //printf("Payload:\n"); 
 //for (i=0; i<pkthdr->len; i++){ 

 //   if ( isprint(packet[i]) ) /* If it is a printable character, print it */
 //       printf("%c ", packet[i]); 
 //   else 
 //       printf(". "); 
 //   
 //    if( (i%16 == 0 && i!=0) || i==pkthdr->len-1 ) 
 //       printf("\n"); 
 // } 
 printf("-----------------------------------------------------------\n");
 printf("\n\n"); 
 return; 
} 



int main(int argc, char *argv[] ){ 
    
 int i=0, count=0; 
 pcap_t *handle = NULL; 
 char errbuf[PCAP_ERRBUF_SIZE];
 char *device=NULL; 
 memset(errbuf,0,PCAP_ERRBUF_SIZE); 

 const u_char *packet;
 struct pcap_pkthdr hdr;     /* pcap.h */

 if( argc > 1){  /* If user supplied interface name, use it. */
    device = argv[1];
 }
 else{  /* Get the name of the first device suitable for capture */ 
    if ( (device = pcap_lookupdev(errbuf)) == NULL){
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(1);
    }
 }

 if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Can't get netmask for device %s\n", device);
    net = 0;
    mask = 0;
 }

 printf("Opening device %s\n", device); 
 if ( (handle = pcap_open_live(device, MAXBYTES2CAPTURE, 1,  512, errbuf)) == NULL){
    fprintf(stderr, "ERROR: %s\n", errbuf);
    exit(1);
 }

 if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
   fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
   return(2);
 }
 if (pcap_setfilter(handle, &fp) == -1) {
   fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
   return(2);
 }

 //packet = pcap_next(handle,&hdr);
 //printf("PACKET: %d\n", packet);

 if ( pcap_loop(handle, -1, processPacket, (u_char *)&count) == -1){
    fprintf(stderr, "ERROR: %s\n", pcap_geterr(handle) );
    exit(1);
 }

return 0; 

} 
