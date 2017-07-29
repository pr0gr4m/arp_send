#include "eth.h"

void build_ether(u_char *frame, struct ether_header *hdr)
{
    memcpy(frame, hdr, ETH_HEADER_LEN);
}
