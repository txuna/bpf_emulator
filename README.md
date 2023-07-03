# BPF EMULATOR FOR USERSPACE  
userspace에서 pcap을 대상으로 실행가능한 프로그램 
현재는 bpf instruction을 뽑아내는 기능 구현

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