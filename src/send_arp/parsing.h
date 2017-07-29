#ifndef PARSING_H
#define PARSING_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include "build.h"

// parse thernet header data
int parse_ethernet(const u_char *frame);
// parse arp header data
int parse_arp(const u_char *packet, struct arp_header *ahdr);

#endif // PARSING_H

