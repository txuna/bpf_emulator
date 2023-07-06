#include "main.h"

void bpf_command_n()
{
    return;
}

void bpf_command_help()
{
    printf("\n> next : execute single step instruction.\n");
    printf("> help : display command help.\n\n");
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

    return NONE;
}

void display_progess(parser_state *pstate)
{
    int index = pstate->bpf_emu.processed_packet_index;
    printf("──────────REGISTER──────────\n");
    printf("A(Accumulator)      : %d\n", pstate->bpf_emu.a);
    printf("X(Index Register)   : %d\n", pstate->bpf_emu.x);
    printf("PC(Program Counter) : %d\n", pstate->bpf_emu.pc);
    printf("─────────DISASSEMBLY─────────\n");
    bpf_dump(pstate);
    printf("───────────PACKET────────────\n");
    dump_hex(pstate->packet_handler->pkt[index].pkt_array, pstate->packet_handler->pkt[index].pkt_len);
    printf("───────────COMMAND───────────\n");
    printf("> ");

    return;
}

void init_bpf_emu(parser_state *pstate)
{
    memset(&pstate->bpf_emu, 0, sizeof(bpf_emu_t));
}

// BPF EMULATING
// bpf ins의 ret을 실행했다면 다시 초기화 진행 및 패킷 다음꺼 가지고 오기 및 해당 패킷의 accept reject 여부 알려주기
void bpf_emulator(parser_state *pstate)
{
    char buffer[MAX_BUFFER] = {0};
    int command = 0;
    printf("BPF EMULATOR v1.0\n");
    int is_running = 1;
    while(is_running)
    {
        display_progess(pstate);
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
                is_running = 0;
                break; 
        }
    }

    printf("FINISHED BPF EMULATOR\n");

    return;
}

void dump_hex(uint8_t* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((uint8_t*)data)[i]);
		if (((uint8_t*)data)[i] >= ' ' && ((uint8_t*)data)[i] <= '~') {
			ascii[i % 16] = ((uint8_t*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}