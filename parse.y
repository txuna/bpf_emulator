%{

#include "main.h"
#include "bpf_macro.h"

//extern int yylex(struct parser_state *p);
//extern int yyparse(struct parser_state *p);
//extern FILE* yyin;

static void yyerror(parser_state *p, const char* s);
%}

%union {
	uint32_t val;
    char *str;
    struct block *blk;
}

%token<val> T_UINT
%token T_IP T_ICMP T_UDP T_TCP T_ARP
%token  T_SRC T_DST
%token  T_HOST T_PORT
%token T_AND T_OR T_NOT
%token T_NEWLINE
%token T_TYPE T_CODE 

%type<val> protocol dir selector value icmp_field 
%type<blk> pred expr state 

%parse-param {parser_state* p}

%{
int yylex();
%}

%left T_OR T_AND
%right T_NOT

%start state

%%

state : expr 
    {
        finish_parse(p, $1);
        p->blk = $1; 
    }
    ;

expr : pred
    {
        $$ = $1;
    }
    | expr T_AND expr
    {
        gen_and($1, $3);
        $$ = $1;
    }
    | expr T_OR expr
    {
        gen_or($1, $3);
        $$ = $1; 
    }
    | T_NOT expr 
    {
        gen_not($2);
        $$ = $2;
    }
    | '(' expr ')'
    {
        $$ = $2;
    }
    ;

pred : protocol 
    {
        $$ = gen_proto_abbrev_internal(p, $1);
    }
    | protocol dir selector value
    {
        if(check_protocol(p, $1, $2, $3, $4) == 1)
        {
            yyerror(p, "None Expected selector\n");
            YYERROR; // throw error 
        }
        $$ = gen_dir_abbrev_internal(p, $1, $2, $3, $4);
    }
    | T_ICMP icmp_field value
    {
        $$ = gen_icmp_field(p, $2, $3);
    }
    ;

icmp_field : T_TYPE 
            {
                $$ = I_TYPE;
            }
            | T_CODE
            {
                $$ = I_CODE;
            }
    
protocol : T_IP 
        {
            $$ = ETHERTYPE_IP;
        }
        | T_TCP
        {
            $$ = Q_TCP;
        }
        | T_UDP
        {
            $$ = Q_UDP;
        }
        | T_ARP
        {
            $$ = ETHERTYPE_ARP;
        }
        | T_ICMP
        {
            $$ = Q_ICMP;
        }
        ;
dir : T_SRC
    {
        $$ = SRC;
    }
    | T_DST 
    {
        $$ = DST;
    }
    ;
    
selector : T_HOST 
        {
            $$ = HOST;
        }
        | T_PORT 
        {
            $$ = PORT;
        }
        ;
        

value : T_UINT
    {
        $$ = $1;
    }
    ;

%%

void yyerror(struct parser_state *p, const char* s) {
	fprintf(stderr, "Parse error: %s\n", s);
}