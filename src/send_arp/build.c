#include "build.h"

/*
 * Prototype : void build_ether(u_char *frame, struct ether_header *hdr)
 * Last Modified 2017/07/30
 * Written by pr0gr4m
 *
 * build ethernet header to frame
 */
void build_ether(u_char *frame, struct ether_header *hdr)
{
    memcpy(frame, hdr, ETH_HEADER_LEN);
}

/*
 * Prototype : void build_arp(u_char *packet, struct arp_header *hdr)
 * Last Modified 2017/07/30
 * Written by pr0gr4m
 *
 * build arp header to packet
 * hardware type, protocol type, hardware length, protocol length is static
 */
void build_arp(u_char *packet, struct arp_header *hdr)
{
    hdr->htype = htons(0x01);
    hdr->ptype = htons(ETHERTYPE_IP);
    hdr->hlen = HWADDR_LEN;
    hdr->plen = PTADDR_LEN;
    memcpy(packet, hdr, ARP_HEADER_LEN);
}

