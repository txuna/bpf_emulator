
all: bpf

bpf: lex.yy.o parse.tab.o main.o node.o bpf_core.o bpf_image.o
	gcc -o bpf -g lex.yy.o parse.tab.o main.o node.o bpf_core.o bpf_image.o 

main.o: main.h main.c 
	gcc -c -o main.o main.c 

lex.yy.o: main.h lex.yy.c 
	gcc -c -o lex.yy.o lex.yy.c 

parse.tab.o: main.h parse.tab.c
	gcc -c -o parse.tab.o parse.tab.c 

node.o : main.h node.c 
	gcc -c -o node.o node.c 

bpf_core.o : main.h bpf_core.c 
	gcc -c -o bpf_core.o bpf_core.c 

bpg_image.o : main.h bpg_image.c
	gcc -c -o bpg_image.o bpf_image.c

clean:
	rm *.o bpf 