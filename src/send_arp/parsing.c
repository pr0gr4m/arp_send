#include "parsing.h"

/*
 * Prototype : int parse_ethernet(const u_char *frame)
 * Last modified 2017/07/30
 * Written by pr0gr4m
 *
 * if ethernet type is arp, return TRUE
 * or return FALSE
 */
int parse_ethernet(const u_char *frame)
{
    struct ether_header *ethdr;

    ethdr = (struct ether_header *)frame;

    if (ntohs(ethdr->ether_type) == ETHERTYPE_ARP)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

/*
 * Prototype : int parse_arp(const u_char *packet, struct arp_header *ahdr)
 * Last Modified 2017/07/30
 * Written by pr0gr4m
 *
 * store arp header to packet
 */
int parse_arp(const u_char *packet, struct arp_header *ahdr)
{
    memcpy(ahdr, packet, ARP_HEADER_LEN);

    return TRUE;
}
