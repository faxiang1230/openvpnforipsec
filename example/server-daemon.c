#include <linux/socket.h>
//#include <linux/in.h>
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
#include <sys/socket.h>
#include <arpa/inet.h>

#include "log.h"
#include "protocol.h"
#include "tun.h"

#define DEBUG 1
#define SERVER_CONF "server-conf"
#define DEF_INTERVAL 5
#define SNAT 1

#define SERVER_IP "10.0.0.160"
#define SERVER_IPMASK "255.255.255.0"
#define IP_OFFSET "0.0.1.0"
int sockfd = 0, tunfd = 0;

void swap_buf(void *src, void *dst, int len) {
	int num = 0;
	u8_t tmp;	
	for(; num < len; num++) {
		tmp = *(u8_t *)(src + num);
		*(u8_t *)(src + num) = *(u8_t *)(dst + num);
		*(u8_t *)(dst + num) = tmp;
	}
}
int forward_packet(void *head, int len) {
	int length = 0;
	struct ip_hdr *packet = head;

	if (packet->proto == PROTO_ESP) {
#if 0
		struct in_addr s_addr;
		memcpy(&s_addr, packet->srcipaddr, 4);
		char testbuf[32];
		sprintf(testbuf, "%s", inet_ntoa(s_addr));
		if(strcmp(testbuf, "10.0.0.161"))
			return;
#endif
		packet = head + sizeof(struct espip_hdr);
		length = decrypt(packet,len - sizeof(struct espip_hdr));
		//TODO
		unsigned int offset = inet_addr(IP_OFFSET);
		*(unsigned int *)(packet->srcipaddr) = *(unsigned int *)(packet->srcipaddr) + offset;
		packet->ipchksum = 0;
		packet->ipchksum = cal_cksum((unsigned short *)packet, ((packet->vhl & 0xf) * 4));
		if(packet->proto == PROTO_UDP) {
			struct uip_udpip_hdr *udp = (struct uip_udpip_hdr *)packet;
			udp->udpchksum = 0;
			udp->udpchksum = cal_udpchksum((unsigned short *)udp);
		} else if(packet->proto == PROTO_TCP) {
			//TODO
			struct uip_tcpip_hdr *tcp = (struct uip_tcpip_hdr *)packet;
			tcp->tcpchksum = 0;
			tcp->tcpchksum = cal_tcpchksum((unsigned short *)tcp);
		}

		if(write(tunfd, packet, length) < length) {
			printf("Write IP packet partially\n");
			return length;
		}
	} else {
		unsigned int offset = inet_addr(IP_OFFSET);
		*(unsigned int *)(packet->destipaddr) = *(unsigned int *)(packet->destipaddr) - offset;
		packet->ipchksum = 0;
		packet->ipchksum = cal_cksum((unsigned short *)packet, ((packet->vhl & 0xf) * 4));

		struct sockaddr_in *server = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
		server->sin_family =AF_INET;
		*((in_addr_t *)packet->srcipaddr) = inet_addr(SERVER_IP);
		memcpy(&server->sin_addr.s_addr, packet->srcipaddr, 4);
		printf("src ip:%s\n", inet_ntoa(server->sin_addr));
		memcpy(&server->sin_addr.s_addr, packet->destipaddr, 4);
		printf("dest ip:%s\n", inet_ntoa(server->sin_addr));
#if 0
		char testbuf[32];
		sprintf(testbuf,"%s",inet_ntoa(server->sin_addr));
		if(strcmp(testbuf, "10.0.0.161"))
			return;
#endif
		show_buf(packet, len);

		int newlen = 0;
		char buf[1500];

		struct espip_hdr *esp = malloc(sizeof(struct espip_hdr));
		memcpy(&esp->ip, packet, sizeof(struct ip_hdr));
		*((in_addr_t*)esp->ip.srcipaddr) = inet_addr("192.168.1.2");
       //TODO ESP encapsulation
        esp->esp.spi = 0;
        esp->esp.seq = 0;
		esp->ip.proto = IPPROTO_ESP;
		esp->ip.ipchksum = 0;

		newlen = (packet->len[0] << 8) + packet->len[1] + sizeof(struct espip_hdr);
		esp->ip.len[0] = newlen >> 8;
		esp->ip.len[1] = newlen & 0xff;

		esp->ip.ipchksum = cal_cksum((unsigned short*)esp, (packet->vhl & 0xf) * 4);

		newlen = encrypt(packet, (packet->len[0] << 8) + packet->len[1]);

		memset(buf, 0, 1500);
		memcpy(buf, esp, sizeof(struct espip_hdr));
		memcpy(buf + sizeof(struct espip_hdr), packet, newlen);
		printf("send local packet and encrypted data ");
		newlen += sizeof(struct espip_hdr);
		show_buf(buf, newlen);

		newlen = sendto(sockfd, buf, newlen, 0, (struct sockaddr*)server, sizeof(struct sockaddr));
		if(newlen < 0)
			printf("send via raw socket,ret:%s\n", strerror(errno));
		else
			printf("send via raw socket,success :%d\n", newlen);
	}
}
int main() {
	struct ifreq ifr;
	char buff[1500];
	int ret = 0, one = 1;
	fd_set reads;
	struct timeval tv;

	tunfd = tun_alloc();
	if (tunfd < 0) {
		printf("open tun failed,exit\n");
		return tunfd;
	} else {
		config_tun(SERVER_CONF);
	}

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
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
			printf("select status:%d\n", status);
		else if (status) {
			if (FD_ISSET(tunfd, &reads)) {
				ret = read(tunfd, buff, sizeof(buff));
				if (ret <=0) {
					printf("read from tun failed\n");
					continue;
				}
				ret = forward_packet(buff, ret);
			}
		} else {
			dbglog("No data within %d seconds", DEF_INTERVAL);
		}
	}

	return 0;
}
