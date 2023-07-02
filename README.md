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
➜  bpf git:(main) ./bpf ip src host 8.8.8.8 and tcp src port 80
ldh [12]
jeq #0x800
ld [26]
jeq #0x8080808
ldh [12]
jeq #0x800
ldb [23]
jeq #0x6
ldh [20]
jset #0x1fff
ldxb 4*([14]&0xf)
ldh [x + 14]
jeq #0x50
```
then show bpf instruction!