#include "parsing.h"

static void print_ether_addr(u_int8_t addr[])
{
    for (int i = 0; i < ADDR_ETH_LEN; i++)
    {
        printf("%02x%c", addr[i], i == 5 ? '\n' : ':');
    }
}

/*
 * Prototype : int parse_ethernet(const u_char *frame)
 * Last modified 2017/07/30
 * Written by pr0gr4m
 *
 * parse src mac addr, dst mac addr
 * if ethernet type is arp, return TRUE
 * or return FALSE
 */
int parse_ethernet(const u_char *frame)
{
    struct ether_header *ethdr;

    ethdr = (struct ether_header *)frame;
    pr_out("Ethernet");

    pr_out_n("Source : ");
    print_ether_addr(ethdr->ether_shost);

    pr_out_n("Destination : ");
    print_ether_addr(ethdr->ether_dhost);

    putchar('\n');

    if (ntohs(ethdr->ether_type) == ETHERTYPE_ARP)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

static void print_ip(const struct in_addr addr)
{
    char buf[BUF_LEN];
    inet_ntop(AF_INET, (const void *)&addr, buf, BUF_LEN);

    if (buf == NULL)
        return;

    puts(buf);
}

/*
 * Prototype : int parse_arp(const u_char *packet, struct arp_header *ahdr)
 * Last Modified 2017/07/30
 * Written by pr0gr4m
 *
 * parse arp header and store to ahdr
 */
int parse_arp(const u_char *packet, struct arp_header *ahdr)
{
    memcpy(ahdr, packet, ARP_HEADER_LEN);

    print_ether_addr(ahdr->sha);
    print_ip(*((const struct in_addr *)ahdr->spa));
    print_ether_addr(ahdr->tha);
    print_ip(*((const struct in_addr *)ahdr->tpa));

    return TRUE;
}
