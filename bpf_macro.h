#ifndef _BPH_H
#define _BPH_H
/*
 * The instruction encondings.
 */
/* instruction classes */
#define BPF_CLASS(code) ((code) & 0x07)
#define		BPF_LD		0x00
#define		BPF_LDX		0x01
#define		BPF_ST		0x02
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define		BPF_RET		0x06
#define		BPF_MISC	0x07

/* ld/ldx fields */
#define BPF_SIZE(code)	((code) & 0x18)
#define		BPF_W		0x00
#define		BPF_H		0x08
#define		BPF_B		0x10
#define BPF_MODE(code)	((code) & 0xe0)
#define		BPF_IMM 	0x00
#define		BPF_ABS		0x20
#define		BPF_IND		0x40
#define		BPF_MEM		0x60
#define		BPF_LEN		0x80
#define		BPF_MSH		0xa0

/* alu/jmp fields */
#define BPF_OP(code)	((code) & 0xf0)
#define		BPF_ADD		0x00
#define		BPF_SUB		0x10
#define		BPF_MUL		0x20
#define		BPF_DIV		0x30
#define		BPF_OR		0x40
#define		BPF_AND		0x50
#define		BPF_LSH		0x60
#define		BPF_RSH		0x70
#define		BPF_NEG		0x80
#define		BPF_JA		0x00
#define		BPF_JEQ		0x10
#define		BPF_JGT		0x20
#define		BPF_JGE		0x30
#define		BPF_JSET	0x40

#define BPF_SRC(code)	((code) & 0x08)
#define		BPF_K		0x00
#define		BPF_X		0x08

/* ret - BPF_K and BPF_X also apply */
#define BPF_RVAL(code)	((code) & 0x18)
#define		BPF_A		0x10

/* misc */
#define BPF_MISCOP(code) ((code) & 0xf8)
#define		BPF_TAX		0x00
#define		BPF_TXA		0x80

#define JMP(c) ((c)|BPF_JMP|BPF_K)

#define IS_RET(code) ((code) && (BPF_RET | BPF_K))

#define ETHER_HEADER_OFFSET 0 
#define IP_HEADER_OFFSET 14

#define Q_DEFAULT 0

#define I_TYPE 14 
#define I_CODE 15

#define Q_ICMP 0x1
#define Q_TCP 0x6 
#define Q_UDP 0x11 
#define ETHERTYPE_IP 0x800 
#define ETHERTYPE_ARP 0x806

// IP_HEADER_OFFSET + IP HEADER LEN 기준
// IP HEADER LEN은 x register에 들어가 있으므로 생략
#define SRC_PORT_OFFSET 14
#define DST_PORT_OFFSET 16

#define SRC_IP_OFFSET 12
#define DST_IP_OFFSET 16

#define IP_PROTOCOL_OFFSET 9 
#define ETHERTYPE_OFFSET 12
#define IP_FRAGMENT_OFFSET 20

#define IP_HEADER_LEN_OFFSET 14

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

#define DIR_IP(dir)	((dir == SRC) ? (SRC_IP_OFFSET) : (DST_IP_OFFSET))
#define DIR_PORT(dir) ((dir == SRC) ? (SRC_PORT_OFFSET) : (DST_PORT_OFFSET))

/*
 * Macros for insn array initializers.
 code들은 위의 매크로들과 | 연산해서 얻음 
 실행시에는 위의 매크로들과 & 연산해서 어떤값들인지 분리 

 jmp제외는 jt와 jf가 0임 
 jmp만 값 세팅
 */
#define BPF_STMT(code, k) { (u_short)(code), 0, 0, k }
#define BPF_JUMP(code, k, jt, jf) { (u_short)(code), jt, jf, k }

#define CHUNK_NUM 1024

/*
BPF_CLASS | BPF_SIZE | BPF_MODE

0x28 => BPF_LD(0x0) | BPF_H(0x8) | BPF_ABS 


addressing mode 
BPF_ABS : a fixex offset 
BPF_IND : packet data at a variable offset 
BPF_IMM : can be constant 


BPF_W : world 
BPF_H : halfworld 
BPF_B : byte

BPF_LD+BPF_W+BPF_ABS  A <- P[k:4]
BPF_LD+BPF_W+BPF_ABS  A <- P[k:4]
BPF_LD+BPF_H+BPF_ABS  A <- P[k:2]
BPF_LD+BPF_B+BPF_ABS  A <- P[k:1]
BPF_LD+BPF_W+BPF_IND  A <- P[X+k:4]
BPF_LD+BPF_H+BPF_IND  A <- P[X+k:2]
BPF_LD+BPF_B+BPF_IND  A <- P[X+k:1]
BPF_LD+BPF_W+BPF_LEN  A <- len
BPF_LD+BPF_IMM	     A <- k
BPF_LD+BPF_MEM	     A <- M[k]


Jump 관련 instruction도 합쳐진거임 

BPF_JMP+BPF_JA	       pc += k
BPF_JMP+BPF_JGT+BPF_K   pc += (A	> k) ? jt : jf
BPF_JMP+BPF_JGE+BPF_K   pc += (A	>= k) ?	jt : jf
BPF_JMP+BPF_JEQ+BPF_K   pc += (A	== k) ?	jt : jf
BPF_JMP+BPF_JSET+BPF_K  pc += (A	& k) ? jt : jf
BPF_JMP+BPF_JGT+BPF_X   pc += (A	> X) ? jt : jf
BPF_JMP+BPF_JGE+BPF_X   pc += (A	>= X) ?	jt : jf
BPF_JMP+BPF_JEQ+BPF_X   pc += (A	== X) ?	jt : jf
BPF_JMP+BPF_JSET+BPF_X  pc += (A	& X) ? jt : jf


BPF_ALU+BPF_ADD+BPF_K  A	<- A + k
BPF_ALU+BPF_SUB+BPF_K  A	<- A - k
BPF_ALU+BPF_MUL+BPF_K  A	<- A * k
BPF_ALU+BPF_DIV+BPF_K  A	<- A / k
BPF_ALU+BPF_AND+BPF_K  A	<- A & k
BPF_ALU+BPF_OR+BPF_K   A	<- A | k
BPF_ALU+BPF_LSH+BPF_K  A	<- A <<	k
BPF_ALU+BPF_RSH+BPF_K  A	<- A >>	k
BPF_ALU+BPF_ADD+BPF_X  A	<- A + X
BPF_ALU+BPF_SUB+BPF_X  A	<- A - X
BPF_ALU+BPF_MUL+BPF_X  A	<- A * X
BPF_ALU+BPF_DIV+BPF_X  A	<- A / X
BPF_ALU+BPF_AND+BPF_X  A	<- A & X
BPF_ALU+BPF_OR+BPF_X   A	<- A | X
BPF_ALU+BPF_LSH+BPF_X  A	<- A <<	X
BPF_ALU+BPF_RSH+BPF_X  A	<- A >>	X
BPF_ALU+BPF_NEG	      A	<- -A
*/

struct bpf_insn {
	int ins_offset;
	uint16_t code;
	uint8_t	jt;
	uint8_t	jf;
	uint32_t k;
};

struct sock_fprog{
    int len; 
	struct bpf_insn bpf[CHUNK_NUM];
};

/*
 * A single statement, corresponding to an instruction in a block.
 */
struct stmt {
	int code;		/* opcode */
	uint32_t k;		/* k field */
	int offset;		/* instruction offset */
};

struct slist {
	struct stmt s;
	struct slist *next;
};


struct block {
	struct slist *stmts;	/* side effect stmts */
	struct stmt s;		/* branch stmt */
	/*
		gen_and같은 경우에는 jt뒤에 붙어야 됨 그래야 참일 때 확인하고 아래 블럭도 and되게 됨
		gen_or같은 경우에는 jf뒤에 붙여야 위의 결과가 실패해도 실행하게 성공하면 안실행하고

		명령어셋에는 JLT나 JLE가 없는데 이는 JGT와 JGE jump set을 사용하여 sense값을 1로 설정하면 됨
		sense값이 1이면 JF가 참이됨	
	*/
	int sense;			/* sense값에 따라 다음 붙일 block이 jt(0)인지 jf(1)인지 정해짐*/
	struct block *jt;		/* edge corresponding to the jt branch */
	struct block *jf;		/* edge corresponding to the jf branch */
	int marked;	//이미 처리했던 블록인지 확인
};


#endif 