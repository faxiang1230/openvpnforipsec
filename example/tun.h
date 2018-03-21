#ifndef MY_TUN_H
#define MY_TUN_H
#include "protocol.h"

#define MAX_MTU 1500
//read data from tun and encap it with esp header,so limit
//tun mtu for avoid ipfragment
#define TUN_MTU (MAX_MTU - sizeof(struct espip_hdr))

int config_tun(char *config);
int tun_alloc();
#endif
