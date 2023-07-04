#include "main.h"

void pcap_parser(const char* file)
{
    file_state_t *file_state = load_pcap(file);
    if(file_state->buffer == NULL)
    {
        return;
    }

    load_packet(file_state);

    free(file_state->buffer);
    free(file_state);
    return;
}

void load_packet(file_state_t *file_state)
{
    int read_packet_num = 0;
    int read_data_bytes = 0;
    pcap_hdr_t *phdr = (pcap_hdr_t*)file_state->buffer;
    printf("Major - Minor : %d - %d\n", phdr->version_major, phdr->version_minor);

    while(1)
    {
        int read_len = sizeof(pcap_hdr_t) + (sizeof(pcaprec_hdr_t) * read_packet_num) + read_data_bytes;
        if(read_len >= file_state->size)
        {
            printf("END\n");
            break;
        }
        pcaprec_hdr_t *rechdr = (pcaprec_hdr_t*)(file_state->buffer + read_len);
        

        printf("packet len : %d\n", rechdr->incl_len);

        // file_state->buffer + read_len + sizeof(pcaprec_hdr_t) 하면 packet data임
        uint8_t *packet_data = file_state->buffer + read_len + sizeof(pcaprec_hdr_t);
        ethernet_t *ether = (ethernet_t*)packet_data;
        printf("ETHER TYPE : 0x%x\n", ntohs(ether->protocol));

        read_packet_num += 1;
        read_data_bytes += rechdr->incl_len;
    }

    return;
}


file_state_t* load_pcap(const char* file)
{
    file_state_t *file_state = (file_state_t*)malloc(sizeof(file_state));
    if(file_state == NULL)
    {
        return NULL;
    }

    int read_byte = 0;
    int fd = open(file, O_RDONLY);
    if(fd == -1)
    {   
        perror("Can't not open file\n");
        return NULL;
    }

    file_state->size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    file_state->buffer = (uint8_t*)malloc(sizeof(uint8_t) * file_state->size);
    if(file_state->buffer == NULL)
    {
        perror("malloc()\n");
        return NULL;
    }
    
    while(1)
    {
        int bytes = read(fd, file_state->buffer+read_byte, READ_BUFFER);
        if(bytes <= 0)
        {
            break; 
        }
        read_byte += bytes;
    }

    return file_state;
}