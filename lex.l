%option noyywrap

%{
#include "main.h"

#define YY_DECL int yylex()

#include "parse.tab.h"

static uint32_t ip_to_int(const char* ipAddress) {
    uint32_t result = 0;
    int segment = 0;
    int shift = 24;

    while (*ipAddress) {
        if (*ipAddress == '.') {
            if (segment > 255) {
                return 0;
            }

            result |= segment << shift;
            segment = 0;
            shift -= 8;
        } else if (*ipAddress >= '0' && *ipAddress <= '9') {
            segment = segment * 10 + (*ipAddress - '0');
        } else {
            return 0;
        }

        ++ipAddress;
    }

    if (segment > 255) {
        return 0;
    }

    result |= segment << shift;
    return result;
}

%}

%%

[ \t]+	; // ignore all whitespace
\n		{return T_NEWLINE;}
[0-9]+		{yylval.val = atoi(yytext); return T_UINT;}
[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ {yylval.val = ip_to_int(yytext); return T_UINT;}
"ip" { return T_IP;}
"icmp" { return T_ICMP;}
"udp" { return T_UDP;}
"tcp" { return T_TCP;}
"arp" { return T_ARP;}

"src" { return T_SRC;}
"dst" { return T_DST;}

"host" { return T_HOST;}
"port" { return T_PORT;}

"and" {return T_AND;}
"or" {return T_OR;}
"not" {return T_NOT;}

"type" { return T_TYPE; }
"code" { return T_CODE; }

. {
    fprintf(stderr, "lexical error ('%s').\n", yytext); 
    exit(1);
};

%%