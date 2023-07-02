# BPF EMULATOR FOR USERSPACE  
userspace에서 pcap을 대상으로 실행가능한 프로그램 

# INSTALL 
```shell
git clone https://github.com/txuna/bpf_emulator.git
cd bpf_emulator/ 
sh build.sh 
./bpf ip and tcp 
```

# EXAMPLE 
```shell
➜  bpf git:(main) ✗ ./bpf ip src host 199.199.199.199 and tcp dst port 80
ldh [12]
jeq #0x800
ld [26]
jeq #0xc7c7c7c7
ldh [12]
jeq #0x800
ldb [23]
jeq #0x6
ldxb 4*([14]&0xf)
ldh [x + 16]
jeq #0x50
```
then show bpf instruction!