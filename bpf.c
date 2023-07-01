#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <linux/filter.h>
 
#define HEXDUMP_COLS 16
#define PACKET_SIZE 4096

#define	ARRAY_SIZE(x)	( sizeof((x))/sizeof((x)[0]) ) // 배열 길이

// ip and dst port 50000
struct sock_filter code[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 10, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 2, 0, 0x00000084 },
    { 0x15, 1, 0, 0x00000006 },
    { 0x15, 0, 6, 0x00000011 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 4, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 1, 0x0000c350 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 },
};

struct sock_fprog bpf = {
    .len = ARRAY_SIZE(code),
    .filter = code,
};

void hexdump(void *mem, unsigned int len)
{
    unsigned int i, j;
    
    for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
    {
        /* print offset */
        if(i % HEXDUMP_COLS == 0)
        {
            printf("0x%06x: ", i);
        }

        /* print hex data */
        if(i < len)
        {
            printf("%02x ", 0xFF & ((char*)mem)[i]);
        }
        else /* end of block, just aligning for ASCII dump */
        {
            printf("   ");
        }
        
        /* print ASCII dump */
        if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
        {
            for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
            {
                if(j >= len) /* end of block, not really printing */
                {
                        putchar(' ');
                }
                else if(isprint(((char*)mem)[j])) /* printable char */
                {
                        putchar(0xFF & ((char*)mem)[j]);        
                }
                else /* other char */
                {
                        putchar('.');
                }
            }
            putchar('\n');
        }
    }
}

int main(void)
{
    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock < 0)
    {
        perror("socket() Error");
        return 1;
    }

    int ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)); 
    if(ret < 0)
    {
        perror("setsockopt() Error");
        close(sock);
        return 1;
    }

    while(1)
    {
        struct sockaddr_in src_addr; 
        socklen_t addrlen = sizeof(src_addr);
        unsigned char packet[PACKET_SIZE] = {0, };
        int recv_len = recvfrom(sock, packet, PACKET_SIZE, 0, (struct sockaddr*)&src_addr, &addrlen);
        if(recv_len < 0)
        {
            perror("recvfrom() Error");
            close(sock);
            return 1;
        }
        hexdump(packet, recv_len);
    }
    
    close(sock);

    return 0;
}
