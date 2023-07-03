#include "main.h"

//block의 s부분 체킹 시 sense값에 따라 jt jf의 stmt list의 첫번째 s의 offset look ahead하기
void gen_bpf_insn(parser_state *pstate)
{
    struct block *b;
    int index = 0;
    for(int i=0; i<pstate->chunk_id; i++)
    {
        b = pstate->chunks[i];
        struct slist *list = b->stmts; 
        while(list)
        {
            struct bpf_insn ins = {list->s.offset, list->s.code, 0, 0, list->s.k};
            pstate->prog.bpf[index] = ins;
            index += 1;
            list = list->next;
        }

        if(b->s.code == (BPF_RET | BPF_K))
        {
            struct bpf_insn ins = {b->s.offset, b->s.code, 0, 0, b->s.k};
            pstate->prog.bpf[index] = ins;
            index += 1;
            continue; 
        }

        struct block *jt, *jf;

        if(!b->sense)
        {
            jt = b->jt; 
            jf = b->jf; 
        }
        else
        {
            jt = b->jf; 
            jf = b->jt;
        }
        // 블럭의 s가 아닌 stmts의 s를 가지고 와야됨 만약 stmts가 NULL이라면 그때 s 
        uint32_t jt_offset, jf_offset = 0; 
        
        jt_offset = jt->stmts != NULL ? jt->stmts->s.offset : jt->s.offset; 
        jf_offset = jf->stmts != NULL ? jf->stmts->s.offset : jf->s.offset;

        struct bpf_insn ins = {b->s.offset, b->s.code, jt_offset, jf_offset, b->s.k};
        pstate->prog.bpf[index] = ins;
        index += 1;
    }
    
    pstate->prog.len = index;
    return;
}

void set_offset_cfg(parser_state *pstate)
{
    int offset = 0;
    struct block *b;
    for(int i=0; i<pstate->chunk_id; i++)
    {
        b = pstate->chunks[i];
        //block의 stmts먼저 offset 체킹
        struct slist *list = b->stmts; 
        while(list)
        {
            list->s.offset = offset;
            list = list->next;
            offset += 1;
        }
        b->s.offset = offset;
        offset += 1;
    }

    // 전체 instruction의 갯수
    pstate->insn_num = offset;

    return;
}

void finish_parse(parser_state *pstate)
{
    struct block *jt_ret, *jf_ret; 
    jt_ret = gen_retblk(pstate, 1); 
    jf_ret = gen_retblk(pstate, 0);

    // chunks 기반으로 sense값과 jt jf가 NULL인 구간 연결? 
    // 2를 빼는 이유는 마지막 retblk 2개
    for(int i=0; i<(pstate->chunk_id)-2; i++)
    {
        struct block *b = pstate->chunks[i];
        if(b->jt == NULL)
        {
            // sense값이 0이면 jt쪽은 True가 됨 
            // sense값이 1이면 jf쪽은 True가 됨
            if(!b->sense)
            {
                b->jt = jt_ret;
            }
            else
            {
                b->jt = jf_ret;
            }
        }
        if(b->jf == NULL)
        {
            // sense값이 0이면 jf는 False
            // sense값이 1이면 jf는 True
            if(!b->sense)
            {
                b->jf = jf_ret;
            }
            else
            {
                b->jf = jt_ret;
            }
        }
    }

    set_offset_cfg(pstate);
    return;
}

struct block* gen_retblk(parser_state *pstate, uint32_t k)
{
    struct block *b = new_block(pstate, BPF_RET | BPF_K, k);
    b->s.k = k;
    return b;
}

struct block* new_block(parser_state *pstate, uint32_t code, uint32_t k)
{
    struct block *b = (struct block*)malloc(sizeof(struct block));
    if(b == NULL)
    {
        return NULL;
    }
    pstate->chunks[pstate->chunk_id] = b;
    pstate->chunk_id++;
    // 이 때 ret 코드를 만들어야 하나? 
    // 그리고 연결할때는 ret 코드 덮어쓰도록?
    b->jt = NULL; 
    b->jf = NULL;
    b->s.code = code;
    b->s.k = k;
    b->sense = 0;
    return b;
}

struct slist* new_stmt(parser_state *pstate, uint32_t code, uint32_t k)
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
    merge(b0, b1, 0);
}

void gen_or(struct block *b0, struct block *b1)
{
    merge(b0, b1, 1);
}


void merge(struct block *b0, struct block *b1, int type)
{
    struct block *curr = b0;
    while(1)
    {
        if(!curr->sense)
        {
            if(curr->jt == NULL)
            {
                break; 
            }
            curr = curr->jt;
        }
        else
        {
            if(curr->jf == NULL)
            {
                break;
            }
            curr = curr->jf;
        }
    }
    // or같은 경우에는 sense값에 따라 false로 이어지는 루틴에 연결해야 true일 땐 확인안하고 
    // false일 때만 연결해서 확인하게
    if(!curr->sense)
    {
        curr->jt = b1;
    }
    else{
        curr->jf = b1;
    }

    if(type == 1)
    {
        curr->sense = !curr->sense;
    }
}

/*
offset : packet offset 
size : load byte size (word, half word, byte)
value : compare value
*/
struct block* gen_cmp(parser_state *pstate, uint32_t offset, uint32_t size, uint32_t value, uint32_t addr_mode)
{
    return gen_ncmp(pstate, BPF_JEQ, offset, size, value, addr_mode);
}

struct block* gen_cmp_gt(parser_state *pstate, uint32_t offset, uint32_t size, uint32_t value, uint32_t addr_mode)
{
    return gen_ncmp(pstate, BPF_JGT, offset, size, value, addr_mode);
}

struct block* gen_cmp_set(parser_state *pstate, uint32_t offset, uint32_t size, uint32_t value, uint32_t addr_mode)
{
    return gen_ncmp(pstate, BPF_JSET, offset, size, value, addr_mode);
}

struct block* gen_ncmp(parser_state *pstate, uint32_t jtype, uint32_t offset, uint32_t size, uint32_t value, uint32_t addr_mode)
{
    struct slist *s; 
    struct block *b; 

    s = gen_load_a(pstate, offset, size, addr_mode);
    b = new_block(pstate, JMP(jtype), value);
    b->stmts = s; 

    return b;
}

struct block* gen_proto_abbrev_internal(parser_state *pstate, uint32_t proto)
{
    struct block *b0;

    switch(proto)
    {
        case Q_TCP:
            b0 = gen_proto(pstate, proto, ETHERTYPE_IP);
            break; 

        case Q_UDP:
            b0 = gen_proto(pstate, proto, ETHERTYPE_IP);
            break; 

        case Q_ICMP:
            b0 = gen_proto(pstate, proto, ETHERTYPE_IP);
            break;

        case ETHERTYPE_IP:
            b0 = gen_linktype(pstate, proto);
            break;

        case ETHERTYPE_ARP:
            b0 = gen_linktype(pstate, proto);
            break;

        default:
            break;
    }

    return b0;
}

// src, dst, all -> port or host
// 그냥 tcp는 IP fragment 유무랑 상관없지만 port및 그 이상 확인할 떄는 필요함
struct block* gen_dir_abbrev_internal(parser_state *pstate, uint32_t proto, uint32_t dir, uint32_t selector, uint32_t k)
{
    struct block *b0, *b1, *b2;
    // protocol 관련 먼저 만들고
    b0 = gen_proto_abbrev_internal(pstate, proto);

    // dir와 selector 만들기 
    switch(selector)
    {
        case HOST:
        {
            b1 = gen_host(pstate, DIR_IP(dir), k);
            gen_and(b0, b1);
        }
        break; 

        case PORT:
        {
            b1 = gen_cmp_set(pstate, ETHER_HEADER_OFFSET + IP_FRAGMENT_OFFSET, BPF_H, 0x1fff, BPF_ABS);
            b2 = gen_port(pstate, DIR_PORT(dir), k);
            gen_and(b1, b2);
            gen_and(b0, b1);
        }
        break;

        default:
            break; 
    }

    return b0;
}


struct block* gen_proto(parser_state *pstate, uint32_t v, uint32_t proto)
{
    struct block *b0, *b1; 
    struct block *b2;

    switch(proto)
    {
        case ETHERTYPE_IP:
            // fragment 0만
            b0 = gen_linktype(pstate, proto);
            b1 = gen_cmp(pstate, IP_HEADER_OFFSET + IP_PROTOCOL_OFFSET, BPF_B, v, BPF_ABS);
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
struct block* gen_linktype(parser_state *pstate, uint32_t ethertype)
{
    // ldh [12]하는 slist만들고 
    // gen_cmp해서 나온것에 넣기
    // ldh밖에 없어서 gen_cmp로만 충분할듯
    struct block *b = gen_cmp(pstate, ETHER_HEADER_OFFSET + ETHERTYPE_OFFSET, BPF_H, ethertype, BPF_ABS);
    return b;
}

struct block* gen_host(parser_state *pstate, uint32_t dir, uint32_t k)
{
    struct block* b = gen_cmp(pstate, IP_HEADER_OFFSET + dir, BPF_W, k, BPF_ABS);
    return b;
}

struct block* gen_port(parser_state *pstate, uint32_t dir, uint32_t k)
{
    struct block *b; 
    struct slist *s; 
    // ldx 4*([14]&0xf)로 x register에 값을 먼저 로드
    s = gen_iphdrlen(pstate); 

    b = gen_cmp(pstate, dir, BPF_H, k, BPF_IND);
    // s instruction이 해당 블럭에서 가장먼저 실행되어야 해서 기존 블럭의 stmts에 가장 앞에 설정
    struct slist *result_s = sappend(b->stmts, s, FIRST);
    b->stmts = result_s;
}

// field is type or code
// IP인지, non fragment인지
struct block* gen_icmp_field(parser_state *pstate, int field, uint32_t k)
{
    struct block *b1, *b2, *b3;
    struct slist *s; 

    b1 = gen_proto_abbrev_internal(pstate, Q_ICMP);
    b2 = gen_cmp_set(pstate, ETHER_HEADER_OFFSET + IP_FRAGMENT_OFFSET, BPF_H, 0x1fff, BPF_ABS);
    gen_and(b1, b2);
    
    s = gen_iphdrlen(pstate);   
    b3 = gen_cmp(pstate, field, BPF_B, k, BPF_IND);
    struct slist *result_s = sappend(b3->stmts, s, FIRST);
    b3->stmts = result_s;

    gen_and(b1, b3); 
    

   return b1; 
}


struct slist* gen_iphdrlen(parser_state *pstate)
{
    struct slist *s = gen_load_x(pstate, ETHER_HEADER_OFFSET + IP_HEADER_LEN_OFFSET, BPF_B);
    return s;
}


// jmp를 위해서는 accumulator에 값을 로드해야됌
struct slist* gen_load_a(parser_state *pstate, uint32_t offset, uint32_t size, uint32_t addr_mode)
{
    struct slist *s1;

    s1 = new_stmt(pstate, BPF_LD | addr_mode | size, offset); 

    return s1;
}

struct slist* gen_load_x(parser_state *pstate, uint32_t offset, uint32_t size)
{
    struct slist *s1; 
    s1 = new_stmt(pstate, BPF_LDX | BPF_MSH | size, offset);
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

void free_bpf_block(parser_state *pstate)
{
    struct block *b; 
    struct slist *s, *prev; 
    for(int i=0; i < pstate->chunk_id; i++)
    {
        b = pstate->chunks[i];
        s = b->stmts;
        while(s)
        {
            prev = s; 
            s = s->next;
            free(prev);
        }
        free(b);
    }

    return;
}


// selector가 proto에 맞는지 확인
int check_protocol(parser_state *pstate, uint32_t proto, uint32_t dir, uint32_t selector, uint32_t k)
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