#ifndef GLUE_H_
#define GLUE_H_

#include "./lib/packetheader.hh"
#include "./lib/raw_sock.h"
#include "./lib/scionpathinfo.hh"


void changeMAC(struct sniff_ethernet *packet, u_char *nicMAC);

void changeIP(struct sniff_ip *packet, unsigned long src);

unsigned long getNicIP(char *dev);

void getMAC(char *dev, u_char *MAC);

void checksum(struct sniff_ip *packet);

#endif