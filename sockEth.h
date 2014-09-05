#ifndef SOCKETH_H_
#define SOCKETH_H_

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

void setUDPH(char *sendbuf, u_char *data, int sport, int dport);

void setTCPH(char *sendbuf, u_char *data, int sport, int dport);

void sendEth(char *ifName, u_int32_t daddr, u_char *dstMAC, u_char *data, int sport, int dprot, u_int8_t protocol);

void printUDP(struct udphdr *udph);

#endif

