#include "main.h"

int main(int argc, char **argv)
{
    if(argc < 2)
    {
        return 1;
    }

    char *command = concatenate_argv(argc, argv);
    parser_state p;
    memset(&p, 0, sizeof(parser_state));
    p.chunk_id = 0;
    p.insn_num = 0;

    int ret = node_parse(command, &p);
    if(ret != 0)
    {
        free(command);
        return 1; 
    }
    gen_bpf_insn(&p);

    packet_handler_t *packet_handler = pcap_parser("packet.pcap");
    if(packet_handler == NULL)
    {
        goto bpf_clean;
    }
    
    p.packet_handler = packet_handler;
    
    //test
    /* 
    for(int i=0; i<p.packet_handler->pkt_num;i++)
    {
        ethernet_t *ether = (ethernet_t*)p.packet_handler->pkt[i].pkt_array;
        printf("ETHER TYPE : 0x%x\n", ntohs(ether->protocol));
    }
    */
    bpf_emulator(&p);

pcap_clean:
    for(int i=0; i<p.packet_handler->pkt_num;i++)
    {
        free(p.packet_handler->pkt[i].pkt_array);
    }
    free(p.packet_handler);

bpf_clean:
    free_bpf_block(&p);
    free(command);
    return 0;

}

int node_parse(const char *string, parser_state *p)
{
    yy_switch_to_buffer(yy_scan_string(string));
    return yyparse(p);
}

char* concatenate_argv(int argc, char* argv[]) {
    int totalLength = 0;
    for (int i = 1; i < argc; i++) {
        totalLength += strlen(argv[i]);
    }

    int spaceLength = argc - 2;
    int resultLength = totalLength + spaceLength + 1; 

    char* result = (char*)malloc(resultLength);
    result[0] = '\0';

    for (int i = 1; i < argc; i++) {
        strcat(result, argv[i]);

        if (i < argc - 1) {
            strcat(result, " ");
        }
    }

    return result;
}
