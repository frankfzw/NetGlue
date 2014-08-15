#ifndef CAPTURE_H_
#define CAPTURE_H_

#include "type.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


#endif