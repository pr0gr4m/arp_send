#include "common.h"
#include "use_pcap.h"
#include "use_socket.h"
#include "arp.h"

int main(int argc, char *argv[])
{
    pcap_arg arg;
    struct ether_header ehdr;
    struct arp_header ahdr;
    struct in_addr addr;

    if (argc < 4)
    {
        pr_err("Usage : %s <interface> <sender ip> <target ip>",
               argv[0]);
        exit(EXIT_FAILURE);
    }

    if (init_handle(&arg, argv[1]))
    {
        exit(EXIT_FAILURE);
    }

    if (set_handle_arp(&arg))
    {
        exit(EXIT_FAILURE);
    }

    if (get_local_addr(&arg, argv[1]))
    {
        exit(EXIT_FAILURE);
    }

    // send arp request
    memset(ehdr.ether_dhost, 0xff, HWADDR_LEN);
    memcpy(ehdr.ether_shost, arg.local_mac, HWADDR_LEN);
    ehdr.ether_type = htons(ETHERTYPE_ARP);
    ahdr.op = htons(ARP_REQUEST);
    memcpy(ahdr.sha, arg.local_mac, HWADDR_LEN);
    memcpy(ahdr.spa, &(arg.local_ip), PTADDR_LEN);
    memset(ahdr.tha, 0x00, HWADDR_LEN);
    inet_pton(AF_INET, argv[2], &addr);
    memcpy(ahdr.tpa, &addr, PTADDR_LEN);
    if (send_arp_packet(&arg, &ehdr, &ahdr))
    {
        exit(EXIT_FAILURE);
    }

    return 0;
}

