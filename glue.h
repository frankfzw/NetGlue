#ifndef GLUE_H_
#define GLUE_H_


#include "type.h"

#include <pcap.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>



void changeMAC(struct sniff_ethernet *packet, u_char *nicMAC);

void changeIP(struct sniff_ip *packet, unsigned long src);

unsigned long getNicIP(char *dev);

void getMAC(char *dev, u_char *MAC);

void checksum(struct sniff_ip *packet);

void convertToSCION(struct sniff_ethernet *packet, u_char *newPkt);

void fromSCION(struct sniff_ethernet *packet, u_char *payload);

int sendPacket(const u_char *packet, char *dev, u_char *dstMAC, unsigned long daddr);

void log(const char *fmt, ...);

void clearLog();

void setDevice(pcap_direction_t direction, bpf_u_int32 net, char *filter_exp, char *dev, pcap_t *handle);

void printMAC(u_char *mac);

void printTCP(struct sniff_tcp *packet);

void printUDP(struct udphdr *udph);

void printICMP(struct icmp6_hdr *icmph);

void printETH(struct sniff_ethernet *eth);

void printIP(struct sniff_ip *iph);



#endif