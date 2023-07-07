#include "main.h"

int main(int argc, char **argv)
{
    if(argc < 3)
    {
        printf("Usage : ./bpf [PCAP FILE] [RULES]\n");
        return 1;
    }

    if(argc > 20)
    {
        printf("Too Many Rules...!\n");
        return 1;
    }

    if(strlen(argv[1]) >= 20)
    {
        printf("Too Long PCAP FILE\n");
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

    packet_handler_t *packet_handler = pcap_parser(argv[1]);
    if(packet_handler == NULL)
    {
        goto bpf_clean;
    }
    
    p.packet_handler = packet_handler;
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
    for (int i = 2; i < argc; i++) {
        totalLength += strlen(argv[i]);
    }

    int spaceLength = argc - 2;
    int resultLength = totalLength + spaceLength + 1; 

    char* result = (char*)malloc(resultLength);
    result[0] = '\0';

    for (int i = 2; i < argc; i++) {
        strcat(result, argv[i]);

        if (i < argc - 2) {
            strcat(result, " ");
        }
    }

    return result;
}
