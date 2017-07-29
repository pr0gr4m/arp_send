#include "use_socket.h"

/*
 * Prototype : int get_local_addr(pcap_arg *arg, char *dev)
 * Last Modified 2017/07/30
 * Written by pr0gr4m
 *
 * get local mac address and ip address
 * and store to arg's member variable
 */
int get_local_addr(pcap_arg *arg, char *dev)
{
    int sock;
    struct ifreq ifr;
    struct addrinfo ai, *ai_ret;
    int rc_gai;
    char err_buf[BUF_LEN];

    memset(&ai, 0, sizeof(ai));
    ai.ai_family = AF_INET;
    ai.ai_socktype = SOCK_DGRAM;
    ai.ai_flags = AI_ADDRCONFIG;

    if ((rc_gai = getaddrinfo(NULL, "0", &ai, &ai_ret)) != 0)
    {
        pr_err("getaddrinfo: %s", gai_strerror(rc_gai));
        return RET_ERR;
    }

    sock = socket(ai_ret->ai_family, ai_ret->ai_socktype, ai_ret->ai_protocol);
    if (sock == -1)
    {
        strerror_r(errno, err_buf, BUF_LEN);
        pr_err("socket: %s", err_buf);
        return RET_ERR;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    // get mac address
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1)
    {
        strerror_r(errno, err_buf, BUF_LEN);
        pr_err("ioctl: %s", err_buf);
        return RET_ERR;
    }
    memcpy(arg->local_mac, ifr.ifr_hwaddr.sa_data, HWADDR_LEN);

    // get ip address
    if (ioctl(sock, SIOCGIFADDR, &ifr) == -1)
    {
        strerror_r(errno, err_buf, BUF_LEN);
        pr_err("ioctl: %s", err_buf);
        return RET_ERR;
    }
    memcpy(&(arg->local_ip), &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr),
           sizeof(struct in_addr));

    close(sock);

    return RET_SUC;
}
