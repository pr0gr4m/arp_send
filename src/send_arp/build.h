#ifndef BUILD_H
#define BUILD_H

#include "common.h"

#define ETH_HEADER_LEN    14
#define ARP_HEADER_LEN  28

#define ARP_REQUEST 0x01
#define ARP_REPLY   0x02

struct arp_header {
    u_int16_t htype;    // Hardware Type
    u_int16_t ptype;    // Protocol Type
    u_char hlen;        // Hardware Address Length
    u_char plen;        // Protocol Address Length
    u_int16_t op;       // Operation Code
    u_char sha[HWADDR_LEN];      // Sender Hardware Address
    u_char spa[PTADDR_LEN];      // Sender Protocol Address
    u_char tha[HWADDR_LEN];      // Target Hardware Address
    u_char tpa[PTADDR_LEN];      // Target Protocol Address
};

// build ethernet header
void build_ether(u_char *frame, struct ether_header *hdr);

// build arp header
void build_arp(u_char *packet, struct arp_header *hdr);

#endif // BUILD_H

