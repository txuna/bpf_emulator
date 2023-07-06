#ifndef _PCAP_H
#define _PCAP_H


#define READ_BUFFER 1024
#define MAX_PACKET 1024

typedef struct file_state_s{
    uint8_t *buffer; 
    int size;
}file_state_t;

typedef struct pcap_hdr_s {
    uint32_t magic_number; /* magic number */
    uint16_t version_major; /* major version number */
    uint16_t version_minor; /* minor version number */
    int32_t thiszone; /* GMT to local correction */
    uint32_t sigfigs; /* accuracy of timestamps */
    uint32_t snaplen; /* max length of captured packets, in octets */
    uint32_t network; /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec; /* timestamp seconds */
    uint32_t ts_usec; /* timestamp microseconds */
    uint32_t incl_len; /* number of octets of packet saved in file */
    uint32_t orig_len; /* actual length of packet */
} pcaprec_hdr_t;

typedef struct packet_s
{
    uint8_t *pkt_array; 
    int pkt_len; 
}packet_t;

typedef struct packet_handler_s
{
    packet_t pkt[MAX_PACKET];
    int pkt_num;
} packet_handler_t;

typedef struct ethernet_s{
	uint8_t dest_mac[6];
	uint8_t src_mac[6];
    uint16_t protocol;
}ethernet_t;

typedef struct iphdr_s
{
    unsigned int version:4;
    unsigned int ihl:4;
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
}iphdr_t;

typedef struct udphdr_s
{
  u_int16_t source;
  u_int16_t dest;
  u_int16_t len;
  u_int16_t check;
}udphdr_t;

typedef struct tcphdr_s
  {
    u_int16_t th_sport;                /* source port */
    u_int16_t th_dport;                /* destination port */
    u_int32_t  th_seq;                /* sequence number */
    u_int32_t  th_ack;                /* acknowledgement number */
    u_int8_t th_off:4;                /* data offset */
    u_int8_t th_x2:4;                /* (unused) */
    u_int8_t th_flags;
#  define TH_FIN        0x01
#  define TH_SYN        0x02
#  define TH_RST        0x04
#  define TH_PUSH        0x08
#  define TH_ACK        0x10
#  define TH_URG        0x20
    u_int16_t th_win;                /* window */
    u_int16_t th_sum;                /* checksum */
    u_int16_t th_urp;                /* urgent pointer */
}tcphdr_t;


#endif