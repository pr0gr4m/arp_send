#ifndef PARSING_H
#define PARSING_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include "common.h"
#include "arp.h"

#define ADDR_ETH_LEN    6
#define ADDR_IP_LEN     4

#define IDX_PROT    9

#define ASCI_CH_ST  0x20
#define ASCI_CH_ED  0x80

// parse and print ethernet header data
int parse_ethernet(const u_char *frame);
// parse and print arp header data
int parse_arp(const u_char *packet, struct arp_header *ahdr);

#endif // PARSING_H

