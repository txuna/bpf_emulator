#ifndef _MAIN_H
#define _MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "bpf_macro.h"

#define NONE 0
#define CHUNK_NUM 1024

typedef struct parser_state{
    struct block *blk;
    struct block *chunks[CHUNK_NUM]; 
    int chunk_id;
}parser_state;


typedef struct yy_buffer_state *YY_BUFFER_STATE;


void yy_switch_to_buffer ( YY_BUFFER_STATE new_buffer  );
YY_BUFFER_STATE yy_scan_string ( const char *yy_str  );

int yyparse(parser_state*);
int node_parse(const char*, parser_state*);
char* concatenate_argv(int argc, char* argv[]);

int check_protocol(parser_state *, uint32_t proto, uint32_t dir, uint32_t selector, uint32_t k);

struct block* new_block(parser_state *, uint32_t code, uint32_t k);
struct slist* new_stmt(parser_state *, uint32_t code, uint32_t k);
void gen_not(struct block *b);
void gen_and(struct block *b0, struct block *b1);
void gen_or(struct block *b0, struct block *b1);
void merge(struct block *b0, struct block *b1, int type);

struct block* gen_cmp(parser_state *, uint32_t offset, uint32_t size, uint32_t value, uint32_t addr_mode);
struct block* gen_cmp_gt(parser_state *, uint32_t offset, uint32_t size, uint32_t value, uint32_t addr_mode);
struct block* gen_cmp_set(parser_state *, uint32_t offset, uint32_t size, uint32_t value, uint32_t addr_mode);
struct block* gen_ncmp(parser_state *, uint32_t jtype, uint32_t offset, uint32_t size, uint32_t value, uint32_t addr_mode);
struct block* gen_proto_abbrev_internal(parser_state *, uint32_t proto);
struct block* gen_dir_abbrev_internal(parser_state *, uint32_t proto, uint32_t dir, uint32_t selector, uint32_t k);
struct block* gen_proto(parser_state *, uint32_t v, uint32_t proto);
struct block* gen_linktype(parser_state *, uint32_t ethertype);
struct slist* gen_load_a(parser_state *, uint32_t offset, uint32_t size, uint32_t addr_mode);
struct block* gen_host(parser_state *, uint32_t dir, uint32_t k);
struct block* gen_port(parser_state *, uint32_t dir, uint32_t k);
struct block* gen_icmp_field(parser_state *, int field, uint32_t k);
struct block* gen_retblk(parser_state *, uint32_t k);

struct slist* gen_iphdrlen(parser_state *);
struct slist* gen_load_x(parser_state *, uint32_t offset, uint32_t size);
struct slist* sappend(struct slist* s0, struct slist* s1, int type);

void finish_parse(parser_state *, struct block *b);
void bpf_dump(struct block *b);
void bpf_disassembly(struct stmt s);
void free_bpf_block(parser_state *);

// 에뮬레이팅과정 리틀엔디안, 빅엔디안 계산필수

#endif

