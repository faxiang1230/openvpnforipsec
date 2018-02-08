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

#define DEBUG 0

#define DEF_INTERVAL 5
#define TUN_DEV "/dev/net/tun"

int sockfd = 0;

int tun_alloc() {
	struct ifreq ifr;
	int fd, err;

	if((fd = open(TUN_DEV, O_RDWR)) < 0) {
		printf("open /dev/net/tun failed\n");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN|IFF_NO_PI;
	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
		printf("ioctl error:%s\n",strerror(err));
		close(fd);
		return err;
	}
	return fd;
}
void swap_buf(void *src, void *dst, int len) {
	int num = 0;
	u8_t tmp;	
	for(; num < len; num++) {
		tmp = *(u8_t *)(src + num);
		*(u8_t *)(src + num) = *(u8_t *)(dst + num);
		*(u8_t *)(dst + num) = tmp;
	}
}
int refill_packet(void *head,int len) {
#if DEBUG
	show_buf(head, len);
#endif
	struct espip_hdr *esp = head;
	struct uip_udpip_hdr *packet = head + sizeof(struct espip_hdr);

	decrypt(packet,len - sizeof(struct espip_hdr));
	dbglog("decrypt %d bytes\n",len - sizeof(struct espip_hdr));
#if DEBUG
	show_buf(packet, len - sizeof(struct espip_hdr));
#endif

	unsigned short *addr = NULL;
	if (verify_ip(packet) < 0) {
		printf("receive broken ip packet\n");
		return -1;
	}
	if(verify_udp(packet) < 0) {
		printf("receive broken udp packet\n");
		return -1;
	}
	printf("Receive from client, Text:\n");
	play_buf(((void*)packet) + sizeof(struct uip_udpip_hdr), ntohs(packet->udplen) - 8);
/*------------------------------------------------------------*/
	memset(((void *)packet) + sizeof(struct uip_udpip_hdr), 'a', ntohs(packet->udplen) - 8);
	swap_buf(&packet->srcport, &packet->destport, sizeof(u16_t));	
	swap_buf(packet->srcipaddr, packet->destipaddr, 2 * sizeof(u16_t));
	swap_buf(&esp->ip.srcipaddr, &esp->ip.destipaddr, 2 * sizeof(u16_t));
	packet->udpchksum = 0;
	packet->ipchksum = 0;

	unsigned int sum = 0, length = 0;
/*------------------------------------------------------------*/
	struct pseudo_udphdr *pu;
	pu = malloc(sizeof(struct pseudo_udphdr));
	memcpy(pu->srcipaddr,packet->srcipaddr, 4);
	memcpy(pu->destipaddr,packet->destipaddr, 4);
	pu->pad = 0;
	pu->proto = 17;
	memcpy(&pu->udplen, &packet->udplen, sizeof(u16_t));

	length = sizeof(struct pseudo_udphdr);
	addr = (unsigned short *)pu;
	while(length > 1) {
		sum += *addr++;
		length -= 2;
	}
	if (length) {
		sum += *(unsigned char *)addr;
	}
	length = htons(packet->udplen);
	addr = &packet->srcport;
	while(length > 1) {
		sum += *addr++;
		length -= 2;
	}
	if (length) {
		sum += *(unsigned char *)addr;
	}

	while (sum >> 16) {
		sum = (sum >> 16) + (sum & 0xffff);
	}
	packet->udpchksum = (unsigned short)(~sum);
/*------------------------------------------------------------*/

	sum = 0;
	addr = (unsigned short *)packet;
	length = sizeof(struct ip_hdr);
	while(length > 1) {
		sum += *addr++;
		length -= 2;
	}
	if (length) {
		sum += *(unsigned char *)addr;
	}

	while (sum >> 16) {
		sum = (sum >> 16) + (sum & 0xffff);
	}
	packet->ipchksum = (unsigned short)(~sum);
/*------------------------------------------------------------*/

	/* check transport IP checksum */
	esp->ip.ipchksum = 0;
	sum = 0;
	addr = (unsigned short *)esp;
	length = sizeof(struct ip_hdr);
	while(length > 1) {
		sum += *addr++;
		length -= 2;
	}
	if (length) {
		sum += *(unsigned char *)addr;
	}

	while (sum >> 16) {
		sum = (sum >> 16) + (sum & 0xffff);
	}
	esp->ip.ipchksum = (unsigned short)(~sum);
/*------------------------------------------------------------*/
#if DEBUG
	show_buf(head, len);
#endif
	return len;
}

int main() {
	debuggerd_init();
	char buff[1500];
	int ret = 0, tunfd = 0, one = 1;
	fd_set reads;
	struct timeval tv;

	tunfd = tun_alloc();
	if (tunfd < 0) {
		printf("open tun failed,exit\n");
		return tunfd;
	}

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP|IPPROTO_UDP|IPPROTO_ICMP);
	if(sockfd < 0) {
		printf("create socket failed:%s\n", strerror(sockfd));
		return sockfd;
	}
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){
		printf("setsockopt failed!\n");  
		return -1; 
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
				}

				dbglog("receive IP packet:%d bytes\n", ret);

				ret = refill_packet(buff + TUN_HEAD, ret - TUN_HEAD);
				if(ret == -1)
					continue;

				dbglog("refill IP packet:%d bytes\n", ret);

				ret = encrypt(buff + sizeof(struct espip_hdr), ret - sizeof(struct espip_hdr));
				ret = ret + sizeof(struct espip_hdr);

				struct sockaddr_in *server = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
				server->sin_family = AF_INET;
				// maybe this looks better:((struct espip_hdr*)buff)->ip.destipaddr
				memcpy(&server->sin_addr.s_addr, buff + 16, 4);

				sendto(sockfd, buff + TUN_HEAD, ret, 0,  (struct sockaddr*)server, sizeof(struct sockaddr));

			}
		} else {
			dbglog("No data within %d seconds", DEF_INTERVAL);
		}
	}

	return 0;
}
