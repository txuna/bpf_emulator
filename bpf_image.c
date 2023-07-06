#include "main.h"

void bpf_dd(parser_state *pstate)
{
    for(int i=0; i<pstate->prog.len; i++)
    {
        struct bpf_insn bpf = pstate->prog.bpf[i];
        printf("(%03d) {0x%x, %d, %d, 0x%x}\n", bpf.ins_offset, bpf.code, bpf.jt, bpf.jf, bpf.k);
    }
}

void bpf_dump(parser_state *pstate)
{
    for(int i=0; i<pstate->prog.len; i++)
    {
        struct bpf_insn bpf = pstate->prog.bpf[i];
        if(bpf.ins_offset == pstate->bpf_emu.pc)
        {
            printf("%c[1;32m",27);
            printf("=>");
            bpf_disassembly(bpf);
            printf("%c[0m",27); 
        }
        else
        {
            printf("%c[1;37m",27);
            bpf_disassembly(bpf);
            printf("%c[0m",27); 
        }
        
    }
}

void bpf_disassembly(struct bpf_insn s)
{
    printf("(%03d) ", s.ins_offset);
    switch(s.code)
    {
        case BPF_LD | BPF_W | BPF_ABS:
            printf("ld [%d]\n", s.k);
            break; 

        case BPF_LD | BPF_H | BPF_ABS:
            printf("ldh [%d]\n", s.k);
            break;

        case BPF_LD | BPF_B | BPF_ABS:
            printf("ldb [%d]\n", s.k);
            break; 

        case BPF_LD | BPF_W | BPF_IND:
            printf("ld [x + %d]\n", s.k);
            break; 

        case BPF_LD | BPF_H | BPF_IND:
            printf("ldh [x + %d]\n", s.k);
            break; 

        case BPF_LD | BPF_B | BPF_IND:
            printf("ldb [x + %d]\n", s.k);
            break; 

        case BPF_LD | BPF_IMM:
            printf("ld #0x%x\n", s.k);
            break; 

        case BPF_LDX | BPF_IMM:
            printf("ldx #0x%x\n", s.k);
            break; 

        case BPF_LDX | BPF_MSH | BPF_B:
            printf("ldxb 4*([%d]&0xf)\n", s.k);
            break; 

        case BPF_LD|BPF_MEM:
            printf("ld M[%d]\n", s.k);
            break; 

        case BPF_LDX|BPF_MEM:
            printf("ldx M[%d]\n", s.k);
            break; 

        case BPF_ST:
            printf("st M[%d]\n", s.k);
            break; 

        case BPF_STX:
            printf("stx M[%d]\n", s.k);
            break; 

        case BPF_ALU|BPF_ADD|BPF_X:
            printf("add\n");
            break; 

        case BPF_ALU|BPF_SUB|BPF_X:
            printf("sub\n");
            break; 

        case BPF_ALU|BPF_MUL|BPF_X:
            printf("mul\n");
            break; 

        case BPF_ALU|BPF_DIV|BPF_X:
            printf("div\n");
            break;      

        case BPF_ALU|BPF_AND|BPF_X:
            printf("and\n");
            break; 

        case BPF_ALU|BPF_OR|BPF_X:
            printf("or\n");
            break;  

        case BPF_ALU|BPF_LSH|BPF_X:
            printf("lsh\n");
            break; 

        case BPF_ALU|BPF_RSH|BPF_X:
            printf("rsh\n");
            break; 

        case BPF_ALU|BPF_ADD|BPF_K:
            printf("add #%d\n", s.k);
            break; 

        case BPF_ALU|BPF_SUB|BPF_K:
            printf("sub #%d\n", s.k);
            break; 

        case BPF_ALU|BPF_MUL|BPF_K:
            printf("mul #%d\n", s.k);
            break; 

        case BPF_ALU|BPF_DIV|BPF_K:
            printf("div #%d\n", s.k);
            break;      

        case BPF_ALU|BPF_AND|BPF_K:
            printf("and #%d\n", s.k);
            break; 

        case BPF_ALU|BPF_OR|BPF_K:
            printf("or #%d\n", s.k);
            break;  

        case BPF_ALU|BPF_LSH|BPF_K:
            printf("lsh #%d\n", s.k);
            break; 

        case BPF_ALU|BPF_RSH|BPF_K:
            printf("rsh #%d\n", s.k);
            break; 
        
        case BPF_RET | BPF_K:
            printf("ret #0x%x\n", s.k);
            break;

        case BPF_JMP | BPF_JEQ | BPF_K:
            printf("jeq #0x%x\t\tjt %d\tjf %d\n", s.k, s.jt, s.jf);
            break; 

        case BPF_JMP | BPF_JGT | BPF_K:
            printf("jgt #0x%x\t\tjt %d\tjf %d\n", s.k, s.jt, s.jf);
            break; 

        case BPF_JMP|BPF_JSET|BPF_K:
            printf("jset #0x%x\t\tjt %d\tjf %d\n", s.k, s.jt, s.jf);
            break;

        default:
            printf("None Exist Instruction.\n");
            break;
    }

    return;
}