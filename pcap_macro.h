#ifndef _PCAP_H
#define _PCAP_H

#define READ_BUFFER 1024

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
} packet_t;

typedef struct ethernet_s{
	uint8_t dest_mac[6];
	uint8_t src_mac[6];
    uint16_t protocol;
}ethernet_t;

#endif