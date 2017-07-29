#include "use_pcap.h"

/*
 * Prototype : int init_handle(pcap_arg *arg)
 * Last Modified 2017/07/12
 * Written by pr0gr4m
 *
 * open pcap handle and store to arg
 * open argument of to_ms is 0
 */
int init_handle(pcap_arg *arg, char *dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (dev == NULL)
    {
        pr_err("Couldn't find default device: %s\n", errbuf);
        return RET_ERR;
    }

    /*
    if (pcap_lookupnet(dev, &(arg->net), &(arg->mask), errbuf) == -1)
    {
        pr_err("Couldn't get netmask for device %s: %s\n", "dum0", errbuf);
        arg->net = 0;
        arg->mask = 0;
    }
    */

    arg->net = 0;
    arg->mask = 0;

    arg->handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
    if (arg->handle == NULL)
    {
        pr_err("Couldn't open device %s: %s \n", "dum0", errbuf);
        return RET_ERR;
    }

    return RET_SUC;
}

/*
 * Prototype : int set_handle_arp(pcap_arg *arg)
 * Last Modified 2017/07/29
 * Written by pr0gr4m
 *
 * set filter of arp to handle
 */
int set_handle_arp(pcap_arg *arg)
{
    struct bpf_program filter;

    if (pcap_compile(arg->handle, &filter, "arp", 1, arg->net) == -1)
    {
        pr_err("Couldn't parse filter arp: %s", pcap_geterr(arg->handle));
        return RET_ERR;
    }

    if (pcap_setfilter(arg->handle, &filter) == -1)
    {
        pr_err("Couldn't install filter arp: %s", pcap_geterr(arg->handle));
        return RET_ERR;
    }

    return RET_SUC;
}

/*
 * Prototype : int close_handle(pcap_arg *arg)
 * Last Modified 2017/07/12
 * Written by pr0gr4m
 *
 * close the handle
 */
int close_handle(pcap_arg *arg)
{
    pcap_close(arg->handle);
    return RET_SUC;
}

/*
 * Prototype : int print_packet_loop(pcap_arg *arg)
 * Last Modified 2017/07/18
 * Written by pr0gr4m
 *
 * capture next packets with handle iteratively
 * ethernet header default length : 14
 * ip header default length : hl * 4
 * tcp header default length : doff * 4
 */
int print_packet_loop(pcap_arg *arg)
{
    struct pcap_pkthdr *header;
    const u_char *frame, *packet, *segment, *payload;
    int ret_next;
    int tot_len, ip_hlen, tcp_doff;

    while (1)
    {
        putchar('\n');
        ret_next = pcap_next_ex(arg->handle, &header, &frame);

        if (ret_next == 0)
            continue;

        if (ret_next != 1)
            break;

        if (frame == NULL)
        {
            pr_err("Don't grab the packet");
        }

        pr_out("* Next Packet Length : [%d]\n", header->len);
        if (parse_ethernet(frame))
        {
            packet = frame + HEAD_ETH_LEN;
            if (parse_ip(packet, &tot_len, &ip_hlen))
            {
                segment = packet + ip_hlen * 4;
                if (parse_tcp(segment, &tcp_doff))
                {
                    if (tot_len + HEAD_ETH_LEN > 60 &&
                            tot_len > ip_hlen * 4 + tcp_doff * 4)
                    {
                        // pass a packet which has no payload data.
                        payload = segment + tcp_doff * 4;
                        parse_data(payload, tot_len -
                                   (ip_hlen * 4 + tcp_doff * 4));

                    }
                }
            }
        }

        puts("======================================================================================");
    }

    return RET_SUC;
}

/*
 * Prototype : int send_arp_packet(pcap_arg *arg)
 * Last Modified 2017/07/29
 * Written by pr0gr4m
 *
 * send arp pacekt
 */
int send_arp_packet(pcap_arg *arg, struct ether_header *ehdr, struct arp_header *ahdr)
{
    u_char frame[ETH_HEADER_LEN + ARP_HEADER_LEN];
    build_ether(frame, ehdr);
    build_arp(frame + ETH_HEADER_LEN, ahdr);

    dumpcode(frame, sizeof(frame));
    if (pcap_sendpacket(arg->handle, frame, sizeof(frame)) == -1)
    {
        pr_err("pcap_sendpacket: %s", pcap_geterr(arg->handle));
        return RET_ERR;
    }

    return RET_SUC;
}

/*
 * Prototype : int recv_arp_packet(pcap_arg *arg)
 * Last Modified 2017/07/29
 * Written by pr0gr4m
 *
 * recv arp packet
 */
int recv_arp_packet(pcap_arg *arg)
{

}

