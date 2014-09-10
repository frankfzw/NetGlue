#ifndef GLUE_H_
#define GLUE_H_


#include "type.h"

#include <pcap.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>



void changeMAC(struct ether_header *packet, u_char *nicMAC, bool isIn);

void changeIP(struct sniff_ip *packet, unsigned long src, bool isIn);

unsigned long getNicIP(char *dev);

void getMAC(char *dev, u_char *MAC);

void checksum(struct sniff_ip *packet);

int convertToSCION(u_char *packet, u_char *newPkt);

int fromSCION(u_char *packet, struct ether_header *eth);

int sendPacket(const u_char *packet, int len, char *dev, u_char *dstMAC, unsigned long daddr, int protocol);

int sendRaw(u_char *sendbuf, int len, char *dev, u_char *dstMAC);

void log(const char *fmt, ...);

void clearLog();

void setDevice(pcap_direction_t direction, bpf_u_int32 net, char *filter_exp, char *dev, pcap_t *handle);

void printMAC(u_char *mac);

void printTCP(struct sniff_tcp *packet);

void printUDP(struct udphdr *udph);

void printICMP(struct icmp6_hdr *icmph);

void printETH(struct ether_header *eth);

void printIP(struct sniff_ip *iph);



#endif