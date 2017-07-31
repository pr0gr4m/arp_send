#ifndef USE_PCAP_H
#define USE_PCAP_H

#define RECV_ITER_N 5

#include "common.h"
#include "parsing.h"
#include "build.h"

// open pcap handle
int init_handle(pcap_arg *arg, char *dev);
// set handle to arp
int set_handle_arp(pcap_arg *arg);
// close pcap handle
int close_handle(pcap_arg *arg);
// send arp request
int send_arp_request(pcap_arg *arg, char *addr_s);
// send arp poison reply
int send_arp_poison(pcap_arg *arg, struct arp_header *ahdr, char *addr_t);
// send arp packet
int send_arp_packet(pcap_arg *arg, struct ether_header *ehdr, struct arp_header *ahdr);
// recv arp packet;
int recv_arp_packet(pcap_arg *arg, struct arp_header *ahdr);

#endif // USE_PCAP_H

