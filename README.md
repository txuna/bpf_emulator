# BPF EMULATOR FOR USERSPACE  
userspace에서 pcap을 대상으로 실행가능한 프로그램 
현재는 bpf instruction을 뽑아내는 기능 구현

## Architecture
기능적인 구현은 아래 2가지의 구현을 가진다.  

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
BPF 기반으로 가상의 패킷 처리 시뮬레이선을 진행하기 위한 나머지부분은 PCAP파싱과 실제 bpf instruction을 기반으로 에뮬레이팅 구현부로 나뉜다.  

1. Implement Pcap Parser 
먼저 pcap을 만들기 위해 아래와 같은 명령어를 사용해 pcap파일을 만든다. 
```Shell
sudo tcpdump -i eth0 -w packet.pcap 
```
만들어진 pcap을 바탕으로 해당 파일의 크기만큼 동적할당을 진행한다. 
그리고 아래 데이터 유형을 만들어 pcap의 데이터를 파싱한다. 
```C
typedef struct packet_s
{
    uint8_t *pkt_array; 
    int pkt_len; 
}packet_t;

typedef struct packet_handler_s
{
    packet_t pkt[MAX_PACKET];
    int pkt_num;
} packet_handler_t;

funcrion
pcaprec_hdr_t *rechdr = (pcaprec_hdr_t*)(file_state->buffer + read_len);

// file_state->buffer + read_len + sizeof(pcaprec_hdr_t) 하면 packet data임
uint8_t *packet_data = file_state->buffer + read_len + sizeof(pcaprec_hdr_t);

packet_handler->pkt[read_packet_num].pkt_array = (uint8_t*)malloc(sizeof(uint8_t) * rechdr->incl_len);
memcpy(packet_handler->pkt[read_packet_num].pkt_array, packet_data, rechdr->incl_len);
packet_handler->pkt[read_packet_num].pkt_len = rechdr->incl_len;
packet_handler->pkt_num += 1;

read_packet_num += 1;
read_data_bytes += rechdr->incl_len;
```
읽은 패킷에 대해 pkt_array에 프로토콜로 처리하는 것이 아닌 Byte Array로서 데이터를 Raw하게 저장을 진행한다.


2. Implement BPF Emulator
사용자의 정의 룰에 따라 만들어진 BPF Instruction을 기반으로 패킷을 시뮬레이션(에뮬레이팅)을 진행한다.  
```Shell
bpf_filter.c 

function 
bpf_emulator()
```

```C
switch(ins.code)
{
	case BPF_LD | BPF_W | BPF_ABS:
		if(ins.k >= packet->pkt_len)
		{
			return BPF_FILTER_FALSE;
		}
		pstate->bpf_emu.a = extrack_long(&packet->pkt_array[ins.k]);
		break; 

	case BPF_LD | BPF_H | BPF_ABS:
		if(ins.k >= packet->pkt_len)
		{
			return BPF_FILTER_FALSE;
		}
		pstate->bpf_emu.a = extract_short(&packet->pkt_array[ins.k]);
		break;
}
```
각 각의 처리할 bpf instruction을 switch문을 통해서 확인 후 각 각에 맞게 처리를 진행한다.   

```C
void display_progess(parser_state *pstate)
{
    size_t pos, bpf_size; 
    pos = -1; 
    bpf_size = -1;
    struct bpf_insn ins = load_bpf_ins_from_offset(pstate);
    load_bpf_pos_and_size(pstate->bpf_emu, ins, &pos, &bpf_size);

    int index = pstate->bpf_emu.processed_packet_index;
    printf("\e[1;1H\e[2J");
    printf("─────────[REGISTER]─────────\n");
    printf("A(Accumulator)      : 0x%x\n", pstate->bpf_emu.a);
    printf("X(Index Register)   : 0x%x\n", pstate->bpf_emu.x);
    printf("PC(Program Counter) : %d\n", pstate->bpf_emu.pc);
    printf("────────[DISASSEMBLY]────────\n");
    bpf_dump(pstate);
    printf("───────[PACKET : %03d]───────\n", index);
    packet_t *packet = load_packet_from_index(pstate);
    dump_hex(packet->pkt_array, packet->pkt_len, pos, bpf_size);
    printf("──────────[COMMAND]──────────\n");
    printf("> ");

    return;
}
```
위의 함수를 통해서 현재의 진행상태에 대해 출력한다.   
  

### INSTALL 
예제 pcap file은 tcpreplay:github의 테스트용 pcap파일입니다. 
```shell
git clone https://github.com/txuna/bpf_emulator.git
cd bpf_emulator/ 
sh build.sh 
./bpf test.pcap tcp src port 80
```

### Grammar 
기본적으로 OR 연산과 AND연산을 제공합니다.  
AND연산은 OR연산보다 우선순위가 높습니다.  
NOT 연산은 제공하지 않으나 기능은 구현되어있어 추후 추가 예정입니다.  

사용가능한 프로토콜   
- IP   
- ARP   
- ICMP   
- TCP  
- UDP   

사용가능한 Direction  
- SRC     
- DST   

사용가능한 Selector(Address)    
- PORT   
- HOST   

룰 예제  
```Shell
ip 
ip src host 1.1.1.1
ip dst host 2.2.2.2
tcp 
tcp src port 80
tcp dst port 80 
udp 
icmp 
icmp code 1
icmp type 1

tcp or icmp code 1
ip and tcp or udp
```

### EXAMPLE 

- case 1
```Shell
./bpf test.pcap tcp src prot 80 
─────────[REGISTER]─────────
A(Accumulator)      : 0x6
X(Index Register)   : 0x0
PC(Program Counter) : 4
────────[DISASSEMBLY]────────
(000) ldh [12]
(001) jeq #0x800                jt 2    jf 10
(002) ldb [23]
(003) jeq #0x6          jt 4    jf 10
=>(004) ldh [20]
(005) jset #0x1fff              jt 10   jf 6
(006) ldxb 4*([14]&0xf)
(007) ldh [x + 14]
(008) jeq #0x50         jt 9    jf 10
(009) ret #0x1
(010) ret #0x0
───────[PACKET : 000]───────
00 1F F3 3C E1 13 F8 1E  DF E5 84 3A 08 00 45 00  00 4F DE 53 40 00 40 06  |  ...<.......:..E..O.S@.@.
47 AB AC 10 0B 0C 4A 7D  13 11 FC 35 01 BB C6 D9  14 D0 C5 1E 2D BF 80 18  |  G.....J}...5........-...
FF FF CB 8C 00 00 01 01  08 0A 1A 7D 84 2C 37 C5  58 B0 15 03 01 00 16 43  |  ...........}.,7.X......C
1A 88 1E FA 7A BC 22 6E  E6 32 7A 53 47 00 A7 5D  CC 64 EA 8E 92           |  ....z."n.2zSG..].d...
──────────[ANALYSIC]─────────
Ethernet Type : IPv4
Source IP : 172.16.11.12
Destination IP : 74.125.19.17
IP Protocol : TCP
Source Port : 13820
Destination Port : 47873
──────────[COMMAND]──────────
> n
```
- case 2
```Shell
./bpf test.pcap test or udp
─────────[REGISTER]─────────
A(Accumulator)      : 0x0
X(Index Register)   : 0x0
PC(Program Counter) : 0
────────[DISASSEMBLY]────────
=>(000) ldh [12]
(001) jeq #0x800                jt 2    jf 9
(002) ldb [23]
(003) jeq #0x6          jt 8    jf 4
(004) ldh [12]
(005) jeq #0x800                jt 6    jf 9
(006) ldb [23]
(007) jeq #0x11         jt 8    jf 9
(008) ret #0x1
(009) ret #0x0
───────[PACKET : 000]───────
00 1F F3 3C E1 13 F8 1E  DF E5 84 3A 08 00 45 00  00 4F DE 53 40 00 40 06  |  ...<.......:..E..O.S@.@.
47 AB AC 10 0B 0C 4A 7D  13 11 FC 35 01 BB C6 D9  14 D0 C5 1E 2D BF 80 18  |  G.....J}...5........-...
FF FF CB 8C 00 00 01 01  08 0A 1A 7D 84 2C 37 C5  58 B0 15 03 01 00 16 43  |  ...........}.,7.X......C
1A 88 1E FA 7A BC 22 6E  E6 32 7A 53 47 00 A7 5D  CC 64 EA 8E 92           |  ....z."n.2zSG..].d...
──────────[ANALYSIC]─────────
Ethernet Type : IPv4
Source IP : 172.16.11.12
Destination IP : 74.125.19.17
IP Protocol : TCP
Source Port : 13820
Destination Port : 47873
──────────[COMMAND]──────────
> n

```
