#include "main.h"

packet_handler_t* pcap_parser(const char* file)
{
    file_state_t *file_state = load_pcap(file);
    if(file_state == NULL)
    {
        return NULL;
    }

    packet_handler_t* packet_handler = load_packet(file_state);

    free(file_state->buffer);
    free(file_state);
    return packet_handler;
}

packet_handler_t* load_packet(file_state_t *file_state)
{
    int read_packet_num = 0;
    int read_data_bytes = 0;
    packet_handler_t *packet_handler = (packet_handler_t*)malloc(sizeof(packet_handler_t));

    if(packet_handler == NULL)
    {
        return NULL;
    }

    memset(packet_handler, 0, sizeof(packet_handler_t));

    pcap_hdr_t *phdr = (pcap_hdr_t*)file_state->buffer;

    while(1)
    {
        // 저장한도 초과
        if(read_packet_num >= MAX_PACKET)
        {
            break; 
        }

        int read_len = sizeof(pcap_hdr_t) + (sizeof(pcaprec_hdr_t) * read_packet_num) + read_data_bytes;
        if(read_len >= file_state->size)
        {
            break;
        }

        pcaprec_hdr_t *rechdr = (pcaprec_hdr_t*)(file_state->buffer + read_len);

        // file_state->buffer + read_len + sizeof(pcaprec_hdr_t) 하면 packet data임
        uint8_t *packet_data = file_state->buffer + read_len + sizeof(pcaprec_hdr_t);
        
        packet_handler->pkt[read_packet_num].pkt_array = (uint8_t*)malloc(sizeof(uint8_t) * rechdr->incl_len);
        memcpy(packet_handler->pkt[read_packet_num].pkt_array, packet_data, rechdr->incl_len);
        packet_handler->pkt[read_packet_num].pkt_len = rechdr->incl_len;
        packet_handler->pkt_num += 1;

        read_packet_num += 1;
        read_data_bytes += rechdr->incl_len;
    }

    return packet_handler;
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
        perror("Can't not open file");
        free(file_state);
        return NULL;
    }

    file_state->size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    file_state->buffer = (uint8_t*)malloc(sizeof(uint8_t) * file_state->size);
    if(file_state->buffer == NULL)
    {
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