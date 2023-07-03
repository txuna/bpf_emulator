#include "main.h"

void bpf_dump(struct block *b)
{
    if(b == NULL)
    {
        return;
    }
    // b->stmts 먼저 풀고 
    // b->s 출력 하고 
    // b->jt or b->jf
    struct slist *list = b->stmts;
    while(list != NULL)
    {
        bpf_disassembly(list->s);
        list = list->next;
    }
    bpf_disassembly(b->s);
    bpf_dump(b->jt);
    // 이때 b의 sense값이 1이면 jt에 ret 0 블럭, 0이라면 ret k 블럭 
    bpf_dump(b->jf);
    // 이때 b의 sense값이 0이면 jt에 ret 0 블럭, 1이라면 ret k 블럭 

    return;
}

void bpf_disassembly(struct stmt s)
{
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
            printf("jeq #0x%x\n", s.k);
            break; 

        case BPF_JMP | BPF_JGT | BPF_K:
            printf("jgt #0x%x\n", s.k);
            break; 

        case BPF_JMP|BPF_JSET|BPF_K:
            printf("jset #0x%x\n", s.k);
            break;

        default:
            printf("None Exist Instruction.\n");
            break;
    }

    return;
}