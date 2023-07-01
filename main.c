#include "main.h"

int main(int argc, char **argv)
{
    if(argc < 2)
    {
        return 1;
    }

    char *command = concatenate_argv(argc, argv);
    parser_state p;

    int ret = node_parse(command, &p);
    if(ret != 0)
    {
        free(command);
        return 1; 
    }
    bpf_dump(p.blk);
    free_bpf_block(p.blk);
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
