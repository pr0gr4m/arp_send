#ifndef ETH_H
#define ETH_H

#include "common.h"

#define ETH_HEADER_LEN    14

void build_ether(u_char *frame, struct ether_header *hdr);

#endif // ETH_H

