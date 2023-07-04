#include "main.h"

void bpf_command_n()
{

}

void bpf_command_help()
{
    printf("> next : execute single step instruction.\n");
    printf("> help : display command help.\n");
    return;   
}

int compare_string_command(char* command)
{
    if(strncmp(command, "help", 4) == 0)
    {   
        return EMU_HELP;
    }
    else if(strncmp(command, "next", 4) == 0)
    {
        return EMU_NEXT;
    }
    else
    {
        return NONE;
    }
}

// BPF EMULATING
void bpf_emulator(parser_state *pstate)
{
    char buffer[MAX_BUFFER] = {0};
    int command = 0;
    printf("BPF EMULATOR v1.0\n");
    int is_running = 1;
    while(is_running)
    {
        printf("> ");
        fgets(buffer, MAX_BUFFER, stdin);
        buffer[strcspn(buffer, "\n")] = 0;
        
        command = compare_string_command(buffer);
        switch(command)
        {
            case EMU_HELP:
                bpf_command_help();
                break; 

            case EMU_NEXT:
                bpf_command_n();
                break; 

            default:
                break;
        }
        
    }
    return;
}