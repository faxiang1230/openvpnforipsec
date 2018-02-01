#include <linux/socket.h>
#include <linux/in.h>
#include <linux/if_tun.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if.h>
#include <errno.h>
#include "log.h"
#include "protocol.h"

#define DEF_INTERVAL 5
#define TUN_DEV "/dev/net/tun"

int tun_alloc() {
	struct ifreq ifr;
	int fd, err;

	if((fd = open(TUN_DEV, O_RDWR)) < 0) {
		printf("open /dev/net/tun failed\n");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN;
	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
		printf("ioctl error:%s\n",strerror(err));
		close(fd);
		return err;
	}
	return fd;
}
void refill_metadata(void *addr) {
	struct ip_hdr *ip = (struct ip_hdr *)addr;
	struct ip_hdr *retip = malloc(ip->len);
	if (ip->proto == PROTO_TCP) {
		struct uip_tcpip_hdr *tcp = (struct uip_tcpip_hdr *)addr;
	} else if (ip->proto == PROTO_UDP) {
		/* source/dst port */
		/*      chksum     */
		struct uip_udpip_hdr *udp = (struct uip_udpip_hdr *)addr;	
		dbglog("receive data:%s\n", addr + sizeof(struct uip_udpip_hdr));
		memset(addr + sizeof(struct uip_udpip_hdr), 97, udp->udplen);
	}
}
void recal_esp(void *head) {

}
int refill_packet(void *head) {
	char *addr = NULL;
	if (verifypacket(head) < 0) {
		printf("receive broken packet\n");
		return -1;
	}
	addr = decapsulate_esp(head);  //|IP|ESP|IP|TCP/UDP|metadata|end|
	refill_metadata(addr);
	recal_esp(head);
}

int main() {
	char buff[1500];
	int ret = 0, tunfd = 0;
	fd_set reads;
	struct timeval tv;

	tunfd = tun_alloc();
	if (tunfd < 0) {
		printf("open tun failed,exit\n");
		exit(tunfd);
	}
	while(1) {
		int status;

		FD_ZERO(&reads);
		FD_SET(tunfd, &reads);
		tv.tv_sec = DEF_INTERVAL;
		tv.tv_usec = 0;

		status = select(tunfd + 1, &reads, NULL, NULL, &tv);

		if (status <= 0)
			printf("select error:%d\n", status);
		else if (status) {
			if (FD_ISSET(tunfd, &reads)) {
				ret = read(tunfd,buff, sizeof(buff));
				if (ret <=0) {
					printf("read from tun failed\n");
					continue;
				} else
					dbglog("receive IP packet:%d bytes\n", ret);
				ret = refill_packet(buff);
				dbglog("refill IP packet:%d bytes\n", ret);
				if (ret > 0) {
					ret = write(tunfd, buff, ret);
					dbglog("rebound to client :%d bytes\n", ret);
				}
			}
		} else {
			dbglog("No data within %d seconds", DEF_INTERVAL);
		}
	}

	return 0;
}
