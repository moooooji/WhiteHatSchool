#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <stdlib.h>

typedef struct {
  unsigned char  ether_dhost[6]; /* destination host address */
  unsigned char  ether_shost[6]; /* source host address */
  unsigned short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
} ethheader;

typedef struct {
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
} ipheader;

typedef struct {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offset;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
}tcpheader;

typedef struct {

    unsigned char message[100];

}tpheader;

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet) 
    {
        ethheader* eth = (ethheader*)packet;
        ipheader* ip;
        tcpheader* tcp;
        tpheader* msg;

        printf("********** ethernet header information **********\n");
        printf("src Mac address : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf("dst Mac address : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
        printf("*******************************************\n");

        if (ntohs(eth->ether_type) == 0x0800) { 
            ip = (ipheader*)(packet + sizeof(ethheader)); 
        }

        int iph_length = ip->iph_ihl * 4;

        printf("********** ip header information **********\n");
        printf("scr Ip address : %s\n", inet_ntoa(ip->iph_sourceip));
        printf("dst Ip address : %s\n", inet_ntoa(ip->iph_destip));
        printf("*******************************************\n");

        if (ip->iph_protocol == IPPROTO_TCP) {
            tcp = (tcpheader*)(packet + sizeof(ethheader) + iph_length);
        }

        int tcph_length = (tcp->tcp_offset >> 4) * 4;
        
        printf("********** tcp header information **********\n");
        printf("src port : %d\n", ntohs(tcp->tcp_sport));
        printf("dst port : %d\n", ntohs(tcp->tcp_dport));
        printf("*******************************************\n");

        msg = (tpheader*)(packet + sizeof(ethheader) + iph_length + tcph_length);

        printf("************** msg information **************\n");
        printf("msg : %s\n", msg->message);
        printf("*********************************************\n");

        return;
    }

int main() {

    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live("ens32", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (!pcap_setfilter(handle, &fp)){ 
      pcap_perror(handle, "Error:");
      
      exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    return 0;
}
