
all: bpf

bpf: lex.yy.o parse.tab.o main.o bpf_core.o bpf_image.o pcap_core.o bpf_filter.o
	gcc -o bpf -g lex.yy.o parse.tab.o main.o bpf_core.o bpf_image.o pcap_core.o bpf_filter.o

main.o: main.h main.c 
	gcc -c -o main.o main.c 

lex.yy.o: main.h lex.yy.c 
	gcc -c -o lex.yy.o lex.yy.c 

parse.tab.o: main.h parse.tab.c
	gcc -c -o parse.tab.o parse.tab.c 

bpf_core.o : main.h bpf_core.c 
	gcc -c -o bpf_core.o bpf_core.c 

bpf_image.o : main.h bpf_image.c
	gcc -c -o bpf_image.o bpf_image.c

pcap_core.o : main.h pcap_core.c 
	gcc -c -o pcap_core.o pcap_core.c

bpf_filter.o : main.h bpf_filter.c
	gcc -c -o bpf_filter.o bpf_filter.c

clean:
	rm *.o bpf 