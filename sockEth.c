#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <errno.h>

#include "sockEth.h"
#include "./lib/raw_sock.h"
 
// #define MY_DEST_MAC0    0xe0
// #define MY_DEST_MAC1    0xb9
// #define MY_DEST_MAC2    0xa5
// #define MY_DEST_MAC3    0x9d
// #define MY_DEST_MAC4    0x12
// #define MY_DEST_MAC5    0x51

#define MY_DEST_MAC0    0x10
#define MY_DEST_MAC1    0xbf
#define MY_DEST_MAC2    0x48
#define MY_DEST_MAC3    0x9c
#define MY_DEST_MAC4    0xaa
#define MY_DEST_MAC5    0xd4

// #define MY_DEST_MAC0    0x68
// #define MY_DEST_MAC1    0x5d
// #define MY_DEST_MAC2    0x43
// #define MY_DEST_MAC3    0x73
// #define MY_DEST_MAC4    0x87
// #define MY_DEST_MAC5    0xd7
 
#define DEFAULT_IF  "wlan0"
#define BUF_SIZ     1024

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}
 
int main(int argc, char *argv[])
{

    char ifName[IFNAMSIZ];
    
    /* Get interface name */
    if (argc > 1)
        strcpy(ifName, argv[1]);
    else
        strcpy(ifName, DEFAULT_IF);

    u_char data[4];
    data[0] = 0xde;
    data[1] = 0xad;
    data[2] = 0xbe;
    data[3] = 0xef;

    u_int32_t daddr = inet_addr("192.168.1.14");

    u_char MAC[6];
    MAC[0] = MY_DEST_MAC0;
    MAC[1] = MY_DEST_MAC1;
    MAC[2] = MY_DEST_MAC2;
    MAC[3] = MY_DEST_MAC3;
    MAC[4] = MY_DEST_MAC4;
    MAC[5] = MY_DEST_MAC5;


    sendEth(ifName, daddr, MAC, data, 3412, 50001, IPPROTO_UDP);
 
    return 0;
}

void setTCPH(char *sendbuf, u_char *data, int sport, int dport)
{
    struct tcphdr *tcph = (struct tcphdr *) (sendbuf + sizeof(struct iphdr) + sizeof(struct ether_header));
    /* UDP Header */
    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->check = 0; // skip
    int len = sizeof(struct tcphdr) + strlen(data);
    //tcph->len = htons(sizeof(struct tcphdr) + strlen(data));
    int tx_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    memcpy(sendbuf + tx_len, data, strlen(data));

    struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
    //UDP checksum
    struct pseudo_header psh;
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));
    int psize = sizeof(struct pseudo_header) + len;
    char *pseudogram = malloc(psize); 
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , len);
    tcph->check = csum( (unsigned short*) pseudogram , psize);
}

void setUDPH(char *sendbuf, u_char *data, int sport, int dport)
{
    struct udphdr *udph = (struct udphdr *) (sendbuf + sizeof(struct iphdr) + sizeof(struct ether_header));
    /* UDP Header */
    udph->source = htons(sport);
    udph->dest = htons(dport);
    udph->check = 0; // skip
    udph->len = htons(sizeof(struct udphdr) + strlen(data));
    int tx_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr);
    memcpy(sendbuf + tx_len, data, strlen(data));

    struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
    //UDP checksum
    struct pseudo_header psh;
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.tcp_length = udph->len;
    int psize = sizeof(struct pseudo_header) + ntohs(udph->len);
    char *pseudogram = malloc(psize); 
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , udph , ntohs(udph->len));
    udph->check = csum( (unsigned short*) pseudogram , psize);
}

void sendEth(char *ifName, u_int32_t daddr, u_char *dstMAC, u_char *data, int sport, int dport, u_int8_t protocol)
{
    int sockfd;
    /* Open RAW socket to send on */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        perror("socket");
    }
 
    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
        perror("SIOCGIFINDEX");

    struct ifreq if_mac;
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
        perror("SIOCGIFHWADDR");

    struct ifreq if_ip;
    memset(&if_ip, 0, sizeof(struct ifreq));
    strncpy(if_ip.ifr_name, ifName, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFADDR, &if_ip) < 0)
        perror("SIOCGIFADDR");

    int tx_len = 0;
    char sendbuf[1024];
    struct ether_header *eh = (struct ether_header *) sendbuf;

    /* Construct the Ethernet header */
    memset(sendbuf, 0, BUF_SIZ);
    /* Ethernet header */
    eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
    eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
    eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
    eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
    eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
    eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
    eh->ether_dhost[0] = dstMAC[0];
    eh->ether_dhost[1] = dstMAC[1];
    eh->ether_dhost[2] = dstMAC[2];
    eh->ether_dhost[3] = dstMAC[3];
    eh->ether_dhost[4] = dstMAC[4];
    eh->ether_dhost[5] = dstMAC[5];
    /* Ethertype field */
    eh->ether_type = htons(ETH_P_IP);
    tx_len += sizeof(struct ether_header);

    struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
    /* IP Header */
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 16; // Low delay
    iph->id = htons(54321);
    iph->ttl = 10; // hops
    iph->protocol = protocol; // UDP
    /* Source IP address, can be spoofed */
    iph->saddr = inet_addr(inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr));
    // iph->saddr = inet_addr("192.168.0.112");
    /* Destination IP address */
    iph->daddr = daddr;
    tx_len += sizeof(struct iphdr);

    //struct udphdr *udph = (struct udphdr *) (sendbuf + sizeof(struct iphdr) + sizeof(struct ether_header));
    /* UDP Header */
    // udph->source = htons(3423);
    // udph->dest = htons(50001);
    // udph->check = 0; // skip
    // tx_len += sizeof(struct udphdr);

 
    /* Packet data */
    // sendbuf[tx_len++] = 0xde;
    // sendbuf[tx_len++] = 0xad;
    // sendbuf[tx_len++] = 0xbe;
    // sendbuf[tx_len++] = 0xef;
    switch (protocol)
    {
        case IPPROTO_UDP:
            tx_len += sizeof(struct udphdr) + strlen(data);
            setUDPH(sendbuf, data, sport, dport);
            //printUDP((struct udphdr *) (sendbuf + sizeof(struct iphdr) + sizeof(struct ether_header)));
            break;
        case IPPROTO_TCP:
            tx_len += sizeof(struct udphdr) + strlen(data);
            setTCPH(sendbuf, data, sport, dport);
            //printUDP((struct udphdr *) (sendbuf + sizeof(struct iphdr) + sizeof(struct ether_header)));
            break;
        default:
            break;
    }

    
 
    /* Length of UDP payload and header */
    //udph->len = htons(tx_len - sizeof(struct ether_header) - sizeof(struct iphdr));
    /* Length of IP payload and header */
    //iph->tot_len = htons(tx_len - sizeof(struct ether_header));
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(data));
    /* Calculate IP checksum on completed header */
    iph->check = csum((unsigned short *)(sendbuf+sizeof(struct ether_header)), sizeof(struct iphdr));

    //UDP checksum
    // struct pseudo_header psh;
    // psh.source_address = iph->saddr;
    // psh.dest_address = iph->daddr;
    // psh.placeholder = 0;
    // psh.protocol = IPPROTO_UDP;
    // psh.tcp_length = udph->len;
    // int psize = sizeof(struct pseudo_header) + ntohs(udph->len);
    // char *pseudogram = malloc(psize); 
    // memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    // memcpy(pseudogram + sizeof(struct pseudo_header) , udph , ntohs(udph->len));
    // udph->check = csum( (unsigned short*) pseudogram , psize);

    struct sockaddr_ll socket_address;
    /* Index of the network device */
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    /* Address length*/
    socket_address.sll_halen = ETH_ALEN;
    /* Destination MAC */
    socket_address.sll_addr[0] = dstMAC[0];
    socket_address.sll_addr[1] = dstMAC[0];
    socket_address.sll_addr[2] = dstMAC[0];
    socket_address.sll_addr[3] = dstMAC[0];
    socket_address.sll_addr[4] = dstMAC[0];
    socket_address.sll_addr[5] = dstMAC[0];
 
    /* Send packet */
    if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
        printf("Send failed\n");
}

void printUDP(struct udphdr* udph)
{
    printf("UDP Header:\n");
    printf("\tSource port: 0x%x\n", udph->source);
    printf("\tDestination port: 0x%x\n", udph->dest);
    printf("\tLength: 0x%x\n", udph->len);
    printf("\tChecksum: 0x%x\n", udph->check);
}