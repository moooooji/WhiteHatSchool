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
    u_char  tcp_offx2;               /* data offset, rsvd */
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

void got_packet(u_char *args, const struct pcap_pkthdr *header, // 2번째 인자에 패킷의 헤더 정보 (길이 등)
                              const u_char *packet) // 1번째 인자에 pcap_loop의 4번째 인자 전달, 3번쨰에 패킷의 실제 데이터 저장
    {
        ethheader* eth = (ethheader*)packet;
	ipheader* ip;
	tcpheader* tcp;
	tpheader* msg;

        printf("********** ethernet header information **********\n");
        printf("src Mac address : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf("dst Mac address : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
        printf("*************************************************\n\n");

        if (ntohs(eth->ether_type) == 0x0800) { // ntohs를 쓰면 컴파일 시 해당 시스템 메모리 저장 방식에 따라 반환값이 달라짐
            ip = (ipheader*)(packet + sizeof(ethheader)); // packet에는 수신된 패킷의 메모리 내 시작 주소를 가리키고 있음, 따라서 ethheader만큼의 크기를 더해줘야 ip헤더에 접근 가능함
        }

        int iph_length = ip->iph_ihl * 4; // ip헤더의 길이는 가변적이고 실제 헤더에 저장된 값은 4를 나눈 값임 

        printf("************* ip header information *************\n");
        printf("scr Ip address : %s\n", inet_ntoa(ip->iph_sourceip));
        printf("dst Ip address : %s\n", inet_ntoa(ip->iph_destip));
        printf("*************************************************\n\n");

        if (ip->iph_protocol == IPPROTO_TCP) {
            tcp = (tcpheader*)(packet + sizeof(ethheader) + iph_length);
        }

        int tcph_length = (tcp->tcp_offx2 >> 4) * 4; // data_offset 필드는 tcp_header의 길이를 4바이트 단위로 나타냄
        
        printf("************* tcp header information ************\n");
        printf("src port : %d\n", ntohs(tcp->tcp_sport));
        printf("dst port : %d\n", ntohs(tcp->tcp_dport));
        printf("*************************************************\n\n");
	
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

    pcap_compile(handle, &fp, filter_exp, 0, net); // filter_exp의 BFP로 컴파일 이를 통해 필터링이 가능해짐
    if (pcap_setfilter(handle, &fp) != 0){ // 오류가 발생하면 -1 반환하므로 필터링 실패 시
      pcap_perror(handle, "Error:"); // 오류메시지 출력 시 앞에 Error : 를 붙임
      
      exit(EXIT_FAILURE); // EXIT_FAILURE는 c, c++ 표준 라이브러리에 정의되어 있으며 1을 가짐
    }

    pcap_loop(handle, -1, got_packet, NULL); // 콜백함수 호출시 3번째 인자에 실제 패킷 데이터가 저장됨

    return 0;
}