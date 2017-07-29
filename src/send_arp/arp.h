#ifndef ARP_H
#define ARP_H

#include "common.h"

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

void build_arp(u_char *packet, struct arp_header *hdr);

#endif // ARP_H

