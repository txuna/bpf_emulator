#ifndef _MAIN_H
#define _MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "bpf_macro.h"

#define NONE 0


// dir 
#define SRC 1 
#define DST 2 
#define ALL 3 

// selector 
#define HOST 1
#define PORT 2 

#define AND 1 
#define OR 2 
#define NOT 3

#define FIRST 1
#define LAST 2


typedef struct parser_state{
    struct block *blk;
}parser_state;


typedef struct yy_buffer_state *YY_BUFFER_STATE;


void yy_switch_to_buffer ( YY_BUFFER_STATE new_buffer  );
YY_BUFFER_STATE yy_scan_string ( const char *yy_str  );

int yyparse(parser_state*);
int node_parse(const char*, parser_state*);
char* concatenate_argv(int argc, char* argv[]);


struct block* new_block(uint32_t code, uint32_t k);
struct slist* new_stmt(uint32_t code, uint32_t k);
void gen_not(struct block *b);
void gen_and(struct block *b0, struct block *b1);
void gen_or(struct block *b0, struct block *b1);
struct block* gen_cmp(uint32_t offset, uint32_t size, uint32_t value);
struct block* gen_cmp_gt(uint32_t offset, uint32_t size, uint32_t value);
struct block* gen_ncmp(uint32_t jtype, uint32_t offset, uint32_t size, uint32_t value);
struct block* gen_proto_abbrev_internal(uint32_t proto);
struct block* gen_proto(uint32_t v, uint32_t proto);
struct block* gen_linktype(uint32_t ethertype);
struct slist* gen_load_a(uint32_t offset, uint32_t size);
struct block* gen_ip(uint32_t dir, uint32_t k);
struct block* gen_port(uint32_t dir, uint32_t k);

struct slist* gen_iphdrlen();
struct slist* gen_load_x(uint32_t offset, uint32_t size);
struct slist* sappend(struct slist* s0, struct slist* s1, int type);

void bpf_dump(struct block *b);
void bpf_disassembly(struct stmt s);

#endif