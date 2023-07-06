#include "main.h"

int extract_short(uint8_t *p)
{
    return ((uint16_t)ntohs(*(const uint16_t *)(p)));
}

int extrack_long(uint8_t* p)
{
    return ((uint32_t)ntohl(*(const uint32_t *)(p)));
}

// 현재 program counter에 맞는 BPF를 뽑아옴
int bpf_command_n(parser_state *pstate)
{
    struct bpf_insn ins = load_bpf_ins_from_offset(pstate);
    if(ins.code == -1)
    {
        return BPF_FILTER_NOT_FETCH_INS;
    }
    
    packet_t *packet = load_packet_from_index(pstate);
    int result = bpf_instruction_filter(pstate, ins, packet);
    return result;
}

void bpf_command_help()
{
    printf("\n> n : execute single step instruction.\n");
    printf("> h : display command help.\n\n");
    return;   
}

int compare_string_command(char* command)
{
    if(strncmp(command, "h", 1) == 0)
    {   
        return EMU_HELP;
    }
    else if(strncmp(command, "n", 1) == 0)
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
    printf("─────────[REGISTER]─────────\n");
    printf("A(Accumulator)      : 0x%x\n", pstate->bpf_emu.a);
    printf("X(Index Register)   : 0x%x\n", pstate->bpf_emu.x);
    printf("PC(Program Counter) : %d\n", pstate->bpf_emu.pc);
    printf("────────[DISASSEMBLY]────────\n");
    bpf_dump(pstate);
    printf("───────[PACKET : %03d]───────\n", index);
    packet_t *packet = load_packet_from_index(pstate);
    dump_hex(packet->pkt_array, packet->pkt_len);
    printf("──────────[COMMAND]──────────\n");
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
                int result = bpf_command_n(pstate);
                if(result == BPF_FILTER_NOT_FETCH_INS)
                {
                    is_running = 0;
                    printf("Cannot Find BPF INSTRUCTION OFFSET\n");
                }
                else if(result == BPF_FILTER_TRUE)
                {
                    int orig = pstate->bpf_emu.processed_packet_index;
                    init_bpf_emu(pstate);
                    pstate->bpf_emu.processed_packet_index = orig + 1;
                    printf("\n\n PAKCET INDEX(%03d) HAS ACCEPT\n\n\n", orig);
                }
                else if(result == BPF_FILTER_FALSE)
                {
                    int orig = pstate->bpf_emu.processed_packet_index;
                    init_bpf_emu(pstate);
                    pstate->bpf_emu.processed_packet_index = orig + 1;
                    printf("\n\n PAKCET INDEX(%03d) HAS REJECT\n\n\n", orig);
                }

                else if(result == BPF_FILTER_CONTINUE)
                {

                }

                break; 

            default:
                is_running = 0;
                break; 
        }

        memset(buffer, 0, MAX_BUFFER);
    }

    printf("FINISHED BPF EMULATOR\n");
    return;
}

void dump_hex(uint8_t* data, size_t size) 
{
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) 
    {
		printf("%02X ", ((uint8_t*)data)[i]);
		if (((uint8_t*)data)[i] >= ' ' && ((uint8_t*)data)[i] <= '~') 
        {
			ascii[i % 16] = ((uint8_t*)data)[i];
		} 
        else 
        {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) 
        {
			printf(" ");
			if ((i+1) % 16 == 0) 
            {
				printf("|  %s \n", ascii);
			} 
            else if (i+1 == size)
             {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) 
                {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) 
                {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

struct bpf_insn load_bpf_ins_from_offset(parser_state *pstate)
{
    for(int i=0; i < pstate->insn_num; i++)
    {
        if(pstate->prog.bpf[i].ins_offset == pstate->bpf_emu.pc)
        {
            return pstate->prog.bpf[i];
        }
    }

    struct bpf_insn bpf;
    bpf.code = -1;
    return bpf;
}

packet_t* load_packet_from_index(parser_state *pstate)
{
    int index = pstate->bpf_emu.processed_packet_index;
    return &pstate->packet_handler->pkt[index];
}

// ret에 도달하면 패킷 프로세스 카운터 + 1
// return 0 - false 
// return 1 - true 
// return 2 - continue
int bpf_instruction_filter(parser_state *pstate, struct bpf_insn ins, packet_t *packet)
{
    int offset = 0;
    switch(ins.code)
    {
        case BPF_LD | BPF_W | BPF_ABS:
            if(ins.k >= packet->pkt_len)
            {
                return BPF_FILTER_FALSE;
            }
            pstate->bpf_emu.a = extrack_long(&packet->pkt_array[ins.k]);
            break; 

        case BPF_LD | BPF_H | BPF_ABS:
            if(ins.k >= packet->pkt_len)
            {
                return BPF_FILTER_FALSE;
            }
            pstate->bpf_emu.a = extract_short(&packet->pkt_array[ins.k]);
            break;

        case BPF_LD | BPF_B | BPF_ABS:
            if(ins.k >= packet->pkt_len)
            {
                return BPF_FILTER_FALSE;
            }
            pstate->bpf_emu.a = packet->pkt_array[ins.k];
            break; 

        case BPF_LD | BPF_W | BPF_IND:
            offset = pstate->bpf_emu.x+ins.k;
            if(offset >= packet->pkt_len)
            {
                return 0;
            }
            pstate->bpf_emu.a = extrack_long(&packet->pkt_array[offset]);
            break; 

        case BPF_LD | BPF_H | BPF_IND:
            offset = pstate->bpf_emu.x+ins.k;
            if(offset >= packet->pkt_len)
            {
                return 0;
            }
            pstate->bpf_emu.a = extract_short(&packet->pkt_array[offset]);
            break; 

        case BPF_LD | BPF_B | BPF_IND: 
            offset = pstate->bpf_emu.x+ins.k;
            if(offset >= packet->pkt_len)
            {
                return BPF_FILTER_FALSE;
            }
            pstate->bpf_emu.a = packet->pkt_array[offset];
            break; 

        case BPF_LD | BPF_IMM:
            pstate->bpf_emu.a = ins.k;
            break; 

        case BPF_LDX | BPF_IMM:
            pstate->bpf_emu.x = ins.k;
            break; 

        case BPF_LDX | BPF_MSH | BPF_B:
            if(ins.k >= packet->pkt_len)
            {
                return BPF_FILTER_FALSE;
            }
            pstate->bpf_emu.x = (packet->pkt_array[ins.k] & 0xf) << 2;
            break; 

        case BPF_LD|BPF_MEM:
            break; 

        case BPF_LDX|BPF_MEM:
            break; 

        case BPF_ST:
            break; 

        case BPF_STX:
            break; 

        case BPF_ALU|BPF_ADD|BPF_X:
            break; 

        case BPF_ALU|BPF_SUB|BPF_X:
            break; 

        case BPF_ALU|BPF_MUL|BPF_X:
            break; 

        case BPF_ALU|BPF_DIV|BPF_X:
            break;      

        case BPF_ALU|BPF_AND|BPF_X:
            break; 

        case BPF_ALU|BPF_OR|BPF_X:
            break;  

        case BPF_ALU|BPF_LSH|BPF_X:
            break; 

        case BPF_ALU|BPF_RSH|BPF_X:
            break; 

        case BPF_ALU|BPF_ADD|BPF_K:
            break; 

        case BPF_ALU|BPF_SUB|BPF_K:
            break; 

        case BPF_ALU|BPF_MUL|BPF_K:
            break; 

        case BPF_ALU|BPF_DIV|BPF_K:
            break;      

        case BPF_ALU|BPF_AND|BPF_K:
            break; 

        case BPF_ALU|BPF_OR|BPF_K:
            break;  

        case BPF_ALU|BPF_LSH|BPF_K:
            break; 

        case BPF_ALU|BPF_RSH|BPF_K:
            break; 
        
        case BPF_RET | BPF_K:
            if(ins.k == 1)
            {
                return BPF_FILTER_TRUE;
            }
            else
            {
                return BPF_FILTER_FALSE;
            }

        case BPF_JMP | BPF_JEQ | BPF_K:
            if(pstate->bpf_emu.a == ins.k)
            {
                pstate->bpf_emu.pc = ins.jt;
            }
            else
            {
                pstate->bpf_emu.pc = ins.jf;
            }
            return BPF_FILTER_CONTINUE;

        case BPF_JMP | BPF_JGT | BPF_K:
            break; 

        case BPF_JMP|BPF_JSET|BPF_K:
            break;

        default:
            printf("None Exist Instruction.\n");
            break;
    }
    
    pstate->bpf_emu.pc += 1;
    return BPF_FILTER_CONTINUE;
}