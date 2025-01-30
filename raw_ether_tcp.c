#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main(int argc, char *argv[])
{
    // Create a raw socket
    int sockfd;
    int one = 1;
    const int *val = &one;

    if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
    {
        perror("socket");
        return 1;
    }
    else
    {
        printf("Socket created\n");
    }

    // Get the index of the sender interface
    struct ifreq if_idx;

    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, "wlp2s0", IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
    {
        perror("SIOCGIFINDEX");
    }
    else
    {
        printf("Index for interface %s is %d\n", if_idx.ifr_name, if_idx.ifr_ifindex);
    }

    // Construct the Ethernet header
    int tx_len = 0;
    char sendbuf[1024];
    struct ethhdr *eh = (struct ethhdr *)sendbuf;
    memset(sendbuf, 0, 1024);

    /* Ethernet header */
    eh->h_source[0] = 0x06;
    eh->h_source[1] = 0x07;
    eh->h_source[2] = 0x08;
    eh->h_source[3] = 0x09;
    eh->h_source[4] = 0x0a;
    eh->h_source[5] = 0x0b;
    eh->h_dest[0] = 0x00;
    eh->h_dest[1] = 0x01;
    eh->h_dest[2] = 0x02;
    eh->h_dest[3] = 0x03;
    eh->h_dest[4] = 0x04;
    eh->h_dest[5] = 0x05;
    eh->h_proto = htons(ETH_P_IP);
    tx_len += sizeof(struct ethhdr);

    // Construct the IP header
    struct iphdr *iph = (struct iphdr *)(sendbuf + sizeof(struct ethhdr));

    /* IP Header */
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 16;
    iph->id = htons(54321);
    iph->ttl = 64;
    iph->protocol = 6; // TCP
    /* Source IP address, can be spoofed */
    iph->saddr = inet_addr("192.168.0.240");
    /* Destination IP address */
    iph->daddr = inet_addr("192.168.0.183");
    tx_len += sizeof(struct iphdr);

    // Construct the TCP packet
    struct tcphdr *tcph = (struct tcphdr *)(sendbuf + sizeof(struct iphdr) + sizeof(struct ethhdr));

    /* TCP Header */
    tcph->source = htons(3423);
    tcph->dest = htons(5342);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5; // TCP header size
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840); /* maximum allowed window size */
    tcph->check = 0;            // skip
    tcph->urg_ptr = 0;
    tx_len += sizeof(struct tcphdr);

    /* Packet data */
    sendbuf[tx_len++] = 0xde;
    sendbuf[tx_len++] = 0xad;
    sendbuf[tx_len++] = 0xbe;
    sendbuf[tx_len++] = 0xef;

    /* Length of IP payload and header */
    iph->tot_len = htons(tx_len - sizeof(struct ethhdr));
    /* Calculate IP checksum on completed header */
    iph->check = csum((unsigned short *)(sendbuf + sizeof(struct ethhdr)), sizeof(struct iphdr) / 2);

    // Pseudo header for TCP checksum calculation
    struct pseudo_header psh;
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + 4); // TCP header + data length

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + 4;
    char *pseudogram = malloc(psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + 4);

    tcph->check = csum((unsigned short *)pseudogram, psize / 2);

    /* Destination address */
    struct sockaddr_ll socket_address;

    /* Index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* Address length*/
    socket_address.sll_halen = ETH_ALEN;
    /* Destination MAC */
    socket_address.sll_addr[0] = 0x00;
    socket_address.sll_addr[1] = 0x01;
    socket_address.sll_addr[2] = 0x02;
    socket_address.sll_addr[3] = 0x03;
    socket_address.sll_addr[4] = 0x04;
    socket_address.sll_addr[5] = 0x05;

    /* Send packet */
    if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) < 0)
    {
        printf("Send failed\n");
    }
    else
    {
        printf("Send success\n");
    }

    free(pseudogram);
    return 0;
}