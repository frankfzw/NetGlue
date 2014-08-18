#ifndef GLUE_H_
#define GLUE_H_

#include "./lib/packetheader.hh"
#include "./lib/raw_sock.h"
#include "./lib/scionpathinfo.hh"
#include "type.h"

void changeMAC(struct sniff_ethernet *packet, u_char *nicMAC);

#endif