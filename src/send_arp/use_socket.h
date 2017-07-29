#ifndef USE_SOCKET_H
#define USE_SOCKET_H

#include "common.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

// get local mac address and ip address
int get_local_addr(pcap_arg *arg, char *dev);

#endif // USE_SOCKET_H

