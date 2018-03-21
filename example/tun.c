#include "tun.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <linux/socket.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <arpa/inet.h>

#define TUN_DEV "/dev/net/tun"

int config_tun(char *config) {
    FILE *fp;
    char *line = NULL;
    size_t len = 0;

    fp = fopen(config, "r");
    if (fp == NULL) {
        printf("Read client config file:%s failed\n", config);
        exit(EXIT_FAILURE);
    }   

    while (getline(&line, &len, fp) != -1) {
        if(system(line) == -1) 
            printf("[FAILED] CONFIG:%s", line);
        else
            printf("CONFIG:%s", line);
    }   

    return 0;
}
int tun_alloc() {
    struct ifreq ifr;
    int fd, err;

    if((fd = open(TUN_DEV, O_RDWR)) < 0) {
        printf("open /dev/net/tun failed\n");
        return -1; 
    }   

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN|IFF_NO_PI;
    if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
        printf("ioctl TUNSETIFF error:%s\n",strerror(err));
        close(fd);
        return err;
    }

    return fd; 
}
