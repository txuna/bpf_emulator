# BPF EMULATOR FOR USERSPACE  
userspace에서 pcap을 대상으로 실행가능한 프로그램 
현재는 bpf instruction을 뽑아내는 기능 구현

## Architecture
기능적인 구현은 아래 2가지의 구현을 가진다.  
(현재 1만 구현)  
### BPF Instruction 생성   
입력된 패킷 필터 규칙 ex) "tcp src port 80"에 대해 제일 먼저 파서가 동작을 실행합니다.
파서는 정해진 규칙에 의해 문법을 파싱하고 문법에 필요한 토큰을 불러옵니다.  
이 떄 토큰을 불러오는 행위를 렉서라고 합니다.   
파서와 렉서는 아래 2개의 파일에서 진행됩니다.  
```
parser.y
lex.l  
```

파서를 통해 입력을 문법에 맞게 처리하고 조건 단위로 하나의 블럭을 만들고 블럭끼리 and 연산 or 연산을 통해 블럭을 Merge합니다.    
조건단위로 진행되는 함수는 gen_cmp이고 gen_cmp를 통해 분기점을 만들어 냅니다.   
그리고 입력에 필요한 instruction을 만들어 내고 해당 블럭에 추가를 진행합니다.   

분기점과 분기점은 JT 또는 JF로 연결합니다.   
JT는 해당 블럭의 연산결과가 참일 때 실행되는 분기이며  
JF는 해당 블럭의 연산결과가 참이 아닐 때 실행되는 분기입니다. 
중요한 것은 block 구조체내의 sense값에 따라 참의 기준이 변경됩니다.   
해당 블럭의 sense의 값이 1이라면 JT가 참이 아닌것이며 JF가 참일 때의 분기로 설정됩니다. 
```C
bpf_code.c 

function
1. gen_cmp 
2. gen_and 
3. gen_or 

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
	int sense;			/* sense값에 따라 다음 붙일 block이 jt(0)인지 jf(1)인지 정해짐*/
	struct block *jt;		/* edge corresponding to the jt branch */
	struct block *jf;		/* edge corresponding to the jf branch */
	int marked;	//이미 처리했던 블록인지 확인
};
```

만들어진 하나의 블럭은 추후 처리하기쉽게 단일 배열로 가공을 진행해야 합니다.  
```C
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
```

즉, 파서의 파싱이 끝나면 parser.y의 최상위 문법은 bpf_core.c에 정의된 finish_parse()함수를 호출하여 bpf instruction을 뽑아냅니다. 

``` 
bpf_core.c 

function 
1. gen_bpf_insn
2. set_offset_cfg
```

이렇게 만들어진 BPF Instruction을 아래의 파일에 있는 함수로 출력을 진행합니다. 
```C
bpf_image.c

function
1. bpf_dd 
2. bpf_dump
```

bpf_dd는 tcpdump의 -dd 옵션과 동일합니다.  
bpf_dump는 tcpdump의 -d 옵션과 동일합니다.  


### BPF Instruction 기반 PCAP 파싱 및 에뮬레이팅  

### INSTALL 
```shell
git clone https://github.com/txuna/bpf_emulator.git
cd bpf_emulator/ 
sh build.sh 
./bpf ip and tcp 
```

### EXAMPLE 

case 1
```shell
➜  bpf git:(main) ✗ ./bpf tcp src port 80
disassembly bpf instruction
(000) ldh [12]
(001) jeq #0x800                jt 2    jf 10
(002) ldb [23]
(003) jeq #0x6          jt 4    jf 10
(004) ldh [20]
(005) jset #0x1fff              jt 6    jf 10
(006) ldxb 4*([14]&0xf)
(007) ldh [x + 14]
(008) jeq #0x50         jt 9    jf 10
(009) ret #0x1
(010) ret #0x0

show bpf bytecode
(000) {0x28, 0, 0, 0xc}
(001) {0x15, 2, 10, 0x800}
(002) {0x30, 0, 0, 0x17}
(003) {0x15, 4, 10, 0x6}
(004) {0x28, 0, 0, 0x14}
(005) {0x45, 6, 10, 0x1fff}
(006) {0xb1, 0, 0, 0xe}
(007) {0x48, 0, 0, 0xe}
(008) {0x15, 9, 10, 0x50}
(009) {0x6, 0, 0, 0x1}
(010) {0x6, 0, 0, 0x0}
```

case 2  
```shell
➜  bpf git:(main) ✗ ./bpf tcp or udp
disassembly bpf instruction
(000) ldh [12]
(001) jeq #0x800                jt 2    jf 9
(002) ldb [23]
(003) jeq #0x6          jt 8    jf 4
(004) ldh [12]
(005) jeq #0x800                jt 6    jf 9
(006) ldb [23]
(007) jeq #0x11         jt 8    jf 9
(008) ret #0x1
(009) ret #0x0

show bpf bytecode
(000) {0x28, 0, 0, 0xc}
(001) {0x15, 2, 9, 0x800}
(002) {0x30, 0, 0, 0x17}
(003) {0x15, 8, 4, 0x6}
(004) {0x28, 0, 0, 0xc}
(005) {0x15, 6, 9, 0x800}
(006) {0x30, 0, 0, 0x17}
(007) {0x15, 8, 9, 0x11}
(008) {0x6, 0, 0, 0x1}
(009) {0x6, 0, 0, 0x0}
```

case 3
```shell
➜  bpf git:(main) ✗ ./bpf ip and tcp or icmp code 1
disassembly bpf instruction
(000) ldh [12]
(001) jeq #0x800                jt 2    jf 16
(002) ldh [12]
(003) jeq #0x800                jt 4    jf 16
(004) ldb [23]
(005) jeq #0x6          jt 15   jf 6
(006) ldh [12]
(007) jeq #0x800                jt 8    jf 16
(008) ldb [23]
(009) jeq #0x1          jt 10   jf 16
(010) ldh [20]
(011) jset #0x1fff              jt 12   jf 16
(012) ldxb 4*([14]&0xf)
(013) ldb [x + 15]
(014) jeq #0x1          jt 15   jf 16
(015) ret #0x1
(016) ret #0x0

show bpf bytecode
(000) {0x28, 0, 0, 0xc}
(001) {0x15, 2, 16, 0x800}
(002) {0x28, 0, 0, 0xc}
(003) {0x15, 4, 16, 0x800}
(004) {0x30, 0, 0, 0x17}
(005) {0x15, 15, 6, 0x6}
(006) {0x28, 0, 0, 0xc}
(007) {0x15, 8, 16, 0x800}
(008) {0x30, 0, 0, 0x17}
(009) {0x15, 10, 16, 0x1}
(010) {0x28, 0, 0, 0x14}
(011) {0x45, 12, 16, 0x1fff}
(012) {0xb1, 0, 0, 0xe}
(013) {0x50, 0, 0, 0xf}
(014) {0x15, 15, 16, 0x1}
(015) {0x6, 0, 0, 0x1}
(016) {0x6, 0, 0, 0x0}
```
then show bpf instruction!