#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    // Create a raw socket
    int sockfd;

    if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
    {
        perror("socket");
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

    // Get the MAC address of the sender interface
    struct ifreq if_mac;

    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, "wlp2s0", IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
    {
        perror("SIOCGIFHWADDR");
    }
    else
    {
        printf("MAC address for interface %s is ", if_mac.ifr_name);
        for (int i = 0; i < 6; i++)
        {
            printf("%02x:", (unsigned char)if_mac.ifr_hwaddr.sa_data[i]);
        }
        printf("\n");
    }

    // Get the IP address of the sender interface
    struct ifreq if_ip;

    memset(&if_ip, 0, sizeof(struct ifreq));
    strncpy(if_ip.ifr_name, "wlp2s0", IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFADDR, &if_ip) < 0)
    {
        perror("SIOCGIFADDR");
    }
    else
    {
        printf("IP address for interface %s is %s\n", if_ip.ifr_name, inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr));
    }

    // Construct the Ethernet header
    int tx_len = 0;
    char sendbuf[1024];
    struct ethhdr *eh = (struct ethhdr *)sendbuf;
    memset(sendbuf, 0, 1024);

    /* Ethernet header */
    eh->h_source[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
    eh->h_source[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
    eh->h_source[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
    eh->h_source[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
    eh->h_source[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
    eh->h_source[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
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
    iph->protocol = 17; // UDP
    /* Source IP address, can be spoofed */
    iph->saddr = inet_addr(inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr));
    // iph->saddr = inet_addr("192.168.0.112");
    /* Destination IP address */
    iph->daddr = inet_addr("192.168.0.111");
    tx_len += sizeof(struct iphdr);

    // Construct the UDP packet
    struct udphdr *udph = (struct udphdr *)(sendbuf + sizeof(struct iphdr) + sizeof(struct ethhdr));

    /* UDP Header */
    udph->source = htons(3423);
    udph->dest = htons(5342);
    udph->check = 0; // skip
    tx_len += sizeof(struct udphdr);

    /* Packet data */
    sendbuf[tx_len++] = 0xde;
    sendbuf[tx_len++] = 0xad;
    sendbuf[tx_len++] = 0xbe;
    sendbuf[tx_len++] = 0xef;

    unsigned short csum(unsigned short *buf, int nwords)
    {
        unsigned long sum;
        for (sum = 0; nwords > 0; nwords--)
            sum += *buf++;
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return (unsigned short)(~sum);
    }

    /* Length of UDP payload and header */
    udph->len = htons(tx_len - sizeof(struct ethhdr) - sizeof(struct iphdr));
    /* Length of IP payload and header */
    iph->tot_len = htons(tx_len - sizeof(struct ethhdr));
    /* Calculate IP checksum on completed header */
    iph->check = csum((unsigned short *)(sendbuf + sizeof(struct ethhdr)), sizeof(struct iphdr) / 2);

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

    return 0;
}