#include "arp.h"

void build_arp(u_char *packet, struct arp_header *hdr)
{
    hdr->htype = htons(0x01);
    hdr->ptype = htons(ETHERTYPE_IP);
    hdr->hlen = HWADDR_LEN;
    hdr->plen = PTADDR_LEN;
    memcpy(packet, hdr, ARP_HEADER_LEN);
}
