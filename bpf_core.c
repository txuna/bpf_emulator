#include "main.h"

struct block* new_block(uint32_t code, uint32_t k)
{
    struct block *b = (struct block*)malloc(sizeof(struct block));
    if(b == NULL)
    {
        return NULL;
    }

    // 이 때 ret 코드를 만들어야 하나? 
    // 그리고 연결할때는 ret 코드 덮어쓰도록?
    b->jt = NULL; 
    b->jf = NULL;
    b->s.code = code;
    b->s.k = k;
    b->sense = 0;

    return b;
}

struct slist* new_stmt(uint32_t code, uint32_t k)
{
    struct slist *s = (struct slist*)malloc(sizeof(struct slist));
    if(s == NULL)
    {
        return NULL;
    }

    s->s.code = code; 
    s->s.k = k;
    s->next = NULL;

    return s;
}

void gen_not(struct block *b)
{
    b->sense = !b->sense;
}

// sense값 따라 세팅 
// sense 값이 0이면 JT, 1이면 JF에 붙이기
// sense값이 1이면 JF가 참 루트
void gen_and(struct block *b0, struct block *b1)
{
    struct block *curr = b0;
    while(curr->jt || curr->jf)
    {
        if(!curr->sense)
        {
            curr = curr->jt;
        }
        else
        {
            curr = curr->jf;
        }
    }
    // and일 때는 sense값에 따라 true로 이어지는 구간에 연결해야 이전계산이 true일 때 확인해서 계산할 수 있게
    if(!curr->sense)
    {
        curr->jt = b1;
    }
    else{
        curr->jf = b1;
    }
}

void gen_or(struct block *b0, struct block *b1)
{
    struct block *curr = b0;
    while(curr->jt || curr->jf)
    {
        if(!curr->sense)
        {
            curr = curr->jt;
        }
        else
        {
            curr = curr->jf;
        }
    }
    // or같은 경우에는 sense값에 따라 false로 이어지는 루틴에 연결해야 true일 땐 확인안하고 
    // false일 때만 연결해서 확인하게
    if(!curr->sense)
    {
        curr->jf = b1;
    }
    else{
        curr->jt = b1;
    }
}

/*
offset : packet offset 
size : load byte size (word, half word, byte)
value : compare value
*/
struct block* gen_cmp(uint32_t offset, uint32_t size, uint32_t value, uint32_t addr_mode)
{
    return gen_ncmp(BPF_JEQ, offset, size, value, addr_mode);
}

struct block* gen_cmp_gt(uint32_t offset, uint32_t size, uint32_t value, uint32_t addr_mode)
{
    return gen_ncmp(BPF_JGT, offset, size, value, addr_mode);
}

struct block* gen_cmp_set(uint32_t offset, uint32_t size, uint32_t value, uint32_t addr_mode)
{
    return gen_ncmp(BPF_JSET, offset, size, value, addr_mode);
}

struct block* gen_ncmp(uint32_t jtype, uint32_t offset, uint32_t size, uint32_t value, uint32_t addr_mode)
{
    struct slist *s; 
    struct block *b; 

    s = gen_load_a(offset, size, addr_mode);
    b = new_block(JMP(jtype), value);
    b->stmts = s; 

    return b;
}

struct block* gen_proto_abbrev_internal(uint32_t proto)
{
    struct block *b0;

    switch(proto)
    {
        case Q_TCP:
            b0 = gen_proto(proto, ETHERTYPE_IP);
            break; 

        case Q_UDP:
            b0 = gen_proto(proto, ETHERTYPE_IP);
            break; 

        case Q_ICMP:
            b0 = gen_proto(proto, ETHERTYPE_IP);
            break;

        case ETHERTYPE_IP:
            b0 = gen_linktype(proto);
            break;

        case ETHERTYPE_ARP:
            b0 = gen_linktype(proto);
            break;

        default:
            break;
    }

    return b0;
}

// src, dst, all -> port or host
// 그냥 tcp는 IP fragment 유무랑 상관없지만 port및 그 이상 확인할 떄는 필요함
struct block* gen_dir_abbrev_internal(uint32_t proto, uint32_t dir, uint32_t selector, uint32_t k)
{
    struct block *b0, *b1, *b2;
    // protocol 관련 먼저 만들고
    b0 = gen_proto_abbrev_internal(proto);

    // dir와 selector 만들기 
    switch(selector)
    {
        case HOST:
        {
            b1 = gen_host(DIR_IP(dir), k);
            gen_and(b0, b1);
        }
        break; 

        case PORT:
        {
            b1 = gen_cmp_set(ETHER_HEADER_OFFSET + IP_FRAGMENT_OFFSET, BPF_H, 0x1fff, BPF_ABS);
            b2 = gen_port(DIR_PORT(dir), k);
            gen_and(b1, b2);
            gen_and(b0, b1);
        }
        break;

        default:
            break; 
    }

    return b0;
}


struct block* gen_proto(uint32_t v, uint32_t proto)
{
    struct block *b0, *b1; 
    struct block *b2;

    switch(proto)
    {
        case ETHERTYPE_IP:
            // fragment 0만
            b0 = gen_linktype(proto);
            b1 = gen_cmp(IP_HEADER_OFFSET + IP_PROTOCOL_OFFSET, BPF_B, v, BPF_ABS);
            gen_and(b0, b1);
            break;

        default:
            break;
    }

    return b0;
}

// 주어진 링크계층 프로토콜이 맞는지 확인하는 블럭
// ldh [12]
// jeq ETHERTYPE
struct block* gen_linktype(uint32_t ethertype)
{
    // ldh [12]하는 slist만들고 
    // gen_cmp해서 나온것에 넣기
    // ldh밖에 없어서 gen_cmp로만 충분할듯
    struct block *b = gen_cmp(ETHER_HEADER_OFFSET + ETHERTYPE_OFFSET, BPF_H, ethertype, BPF_ABS);
    return b;
}

struct block* gen_host(uint32_t dir, uint32_t k)
{
    struct block* b = gen_cmp(IP_HEADER_OFFSET + dir, BPF_W, k, BPF_ABS);
    return b;
}

struct block* gen_port(uint32_t dir, uint32_t k)
{
    struct block *b; 
    struct slist *s; 
    // ldx 4*([14]&0xf)로 x register에 값을 먼저 로드
    s = gen_iphdrlen(); 

    b = gen_cmp(dir, BPF_H, k, BPF_IND);
    // s instruction이 해당 블럭에서 가장먼저 실행되어야 해서 기존 블럭의 stmts에 가장 앞에 설정
    struct slist *result_s = sappend(b->stmts, s, FIRST);
    b->stmts = result_s;
}

struct slist* gen_iphdrlen()
{
    struct slist *s = gen_load_x(ETHER_HEADER_OFFSET + IP_HEADER_LEN_OFFSET, BPF_B);
    return s;
}


// jmp를 위해서는 accumulator에 값을 로드해야됌
struct slist* gen_load_a(uint32_t offset, uint32_t size, uint32_t addr_mode)
{
    struct slist *s1;

    s1 = new_stmt(BPF_LD | addr_mode | size, offset); 

    return s1;
}

struct slist* gen_load_x(uint32_t offset, uint32_t size)
{
    struct slist *s1; 
    s1 = new_stmt(BPF_LDX | BPF_MSH | size, offset);
    return s1;
}

struct slist* sappend(struct slist* s0, struct slist* s1, int type)
{
    // s0에 s1을 연결 
    if(type == LAST)
    {
        struct slist *p = s0; 
        while(p->next)
        {
            p = p->next;
        }
        p->next = s1;
    }
    // s1에 s0을 연결
    else
    {
        s1->next = s0;
    }
}

void free_bpf_block(struct block *blk)
{
    if(blk == NULL)
    {
        return;
    }

    free_bpf_block(blk->jt);
    free_bpf_block(blk->jf);

    // stmts 먼저 free.
    struct slist *cur = blk->stmts; 
    while(cur)
    {
        struct slist* prev = cur; 
        cur = cur->next;
        free(prev);
    }
    free(blk);
    return;
}


// selector가 proto에 맞는지 확인
int check_protocol(uint32_t proto, uint32_t dir, uint32_t selector, uint32_t k)
{
    if(proto == ETHERTYPE_ARP)
    {
        return 1;
    }

    if(proto == Q_ICMP || proto == ETHERTYPE_IP)
    {
        if(selector != HOST)
        {
            return 1;
        }
    }

    return 0;
}