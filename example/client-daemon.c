#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <linux/socket.h>
#include <linux/if_tun.h>
#include <linux/icmp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "client.h"
#include "log.h"
#include "protocol.h"
#include "tun.h"

#define DNAT 1
int parse_packet(struct list_head *list) {
	struct list_head *packet, *next;
	int ret = DISPATCH_NO_PACKET;
	//iterate 'tun' list and dispatch to user_data_list/ipsec_data_list
	list_for_each_safe(packet, next, list) {
		struct rcvpacket *data = list_entry(packet, struct rcvpacket, head);
		ret |= DISPATCH_USER_PACKET;
		list_del(packet);
		list_add(packet, &user_data_list);
	}
	return ret;
}
static void *readtun(void *arg __attribute__((unused))) {
	int nread;
	fd_set rfds;
	struct timeval tv;

	tunfd = tun_alloc();
	if (tunfd < 0) {
		exit(tunfd);
	} else
		config_tun(CLIENTCONF);

	while(1) {
		struct rcvpacket *rcv;
		rcv = (struct rcvpacket *)malloc(sizeof(struct rcvpacket));
		INIT_LIST_HEAD(&rcv->head);
		rcv->packet = malloc(TUN_MTU);

		FD_ZERO(&rfds);
		FD_SET(tunfd, &rfds);
		tv.tv_sec = DEF_INTERVAL_SEC;
		tv.tv_usec = DEF_INTERVAL_MSEC;

		int retval = select(tunfd + 1, &rfds, NULL, NULL, &tv);
		if (retval == -1)
			perror("select error\n");
		else if (retval) {
			if(FD_ISSET(tunfd, &rfds)) {
				nread = read(tunfd, rcv->packet, TUN_MTU);
				if (nread <=0) {
					printf("read from tun failed\n");
					continue;
				}

				pthread_mutex_lock(&recv_mut);
				list_add_tail(&rcv->head, &tun);
				pthread_cond_signal(&recv_cond);
				pthread_mutex_unlock(&recv_mut);
			}
		} else {
			dbglog("No data within %d seconds.\n", DEF_INTERVAL_SEC);
		}
	}
}

static void *dispatch_packet(void *arg __attribute__((unused))) {
	while(1) {
		pthread_mutex_lock(&recv_mut);
		pthread_cond_wait(&recv_cond, &recv_mut);
		pthread_mutex_unlock(&recv_mut);
		int status = parse_packet(&tun);

		if (status & DISPATCH_ESP_PACKET) {
			pthread_mutex_lock(&ipsec_mut);
			pthread_cond_signal(&ipsec_cond);
			pthread_mutex_unlock(&ipsec_mut);
		}
		if (status & DISPATCH_USER_PACKET) {
			pthread_mutex_lock(&user_mut);
			pthread_cond_signal(&user_cond);
			pthread_mutex_unlock(&user_mut);
		}
	}
}
static void *ipsec_packet(void *arg __attribute__((unused))) {
	char buff[MAX_MTU];
	int len = 0, ret = 0;
	struct sockaddr_in client;

	int rcvsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ESP);
	if(rcvsockfd < 0) {
		printf("create socket failed:%s\n", strerror(rcvsockfd));
		exit(-1);
	}

	while (1) {
		memset(buff, 0, MAX_MTU);
		ret = recvfrom(rcvsockfd, buff, MAX_MTU, 0, (struct sockaddr*)&client, &len);
		if(ret > 0) {
			len = decrypt(buff + sizeof(struct espip_hdr), ret - sizeof(struct espip_hdr));
			
			if(((struct ip_hdr*)buff)->proto == PROTO_ESP) {
#if DEBUG_ENCRYPT
				printf("Incoming encrpyted METADATA ");
				show_buf(buff + sizeof(struct espip_hdr), len);
#endif
#if DNAT
				struct ip_hdr *addr = (struct ip_hdr *)(buff + sizeof(struct espip_hdr));
				*(unsigned int *)(addr->srcipaddr) = *(unsigned int *)(addr->srcipaddr) + inet_addr(IP_OFFSET);
				addr->ipchksum = 0;
				addr->ipchksum = cal_cksum((unsigned short *)addr, ((addr->vhl & 0xf) * 4));	

				if(addr->proto == PROTO_UDP) {
					struct uip_udpip_hdr *udp = (struct uip_udpip_hdr *)addr;
					udp->udpchksum = 0;
					udp->udpchksum = cal_udpchksum((unsigned short *)udp);
				} else if(addr->proto == PROTO_TCP) {
					struct uip_tcpip_hdr *tcp = (struct uip_tcpip_hdr *)addr;
					tcp->tcpchksum = 0;
					tcp->tcpchksum = cal_tcpchksum((unsigned short *)tcp);
				}
#endif
#if DEBUG_ENCRYPT
				printf("Incoming decrpyted METADATA ");
				show_buf(buff + sizeof(struct espip_hdr), len);
#endif
				ret = write(tunfd, buff + sizeof(struct espip_hdr), len);
				if (ret < len)
					printf("receive packet:%d bytes, write packet:%d bytes, failed:%d\n", len, ret, len - ret);
			}
		}
	}   
}
/*
 * encapsulate IP pakcet of user's normal data
 */
static void *user_packet(void *arg __attribute__((unused))) {
	int one = 1;
	unsigned int newlen = 0;
	struct sockaddr_in *server = NULL;
	struct list_head *packet,*next;
	char buf[MAX_MTU];

	server = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	server->sin_family =AF_INET;
	server->sin_addr.s_addr = inet_addr(SERVER_IP);

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP|IPPROTO_UDP|IPPROTO_ICMP);
	if (sockfd < 0) {
		printf("create socket failed:%s\n", strerror(errno));
		exit(-1);
	}
	/* IP_HDRINCL: userspace encapsulate IP header other than kernel prepend IP header */
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){  
        printf("setsockopt failed, exit!\n");  
        exit(-1);
    }

	while(1) {
		pthread_mutex_lock(&user_mut);
		pthread_cond_wait(&user_cond, &user_mut);
		pthread_mutex_unlock(&user_mut);

		//iterate 'tun' list and dispatch to user_data_list/ipsec_data_list
		list_for_each_safe(packet, next, &user_data_list) {
			struct rcvpacket *data = list_entry(packet, struct rcvpacket, head);
			struct ip_hdr *addr = data->packet + TUN_HEAD;

			//TODO
			// I don't consider ipv6
			if((addr->vhl >> 4) == IPV6_VERSION)
				goto remove_packet;

#if DEBUG_USER_PACKET
			printf("GET data from user:\n");
			show_buf(addr, (addr->len[0] << 8) + addr->len[1]);
#endif	
			//encapsulate ip packet with tunnel ESP mode
			//TODO

			//struct espip_hdr *esp = malloc(sizeof(struct espip_hdr));
			memset(buf, 0, MAX_MTU);
			struct espip_hdr *esp = (struct espip_hdr *)buf;
			memcpy(&esp->ip, addr, sizeof(struct ip_hdr));
#if DNAT
			{
				//reverse DNAT from 10.0.1.161->10.0.0.161,then reset checksum(TCP/UDP)
				unsigned int offset = inet_addr(IP_OFFSET);
				*(unsigned int *)(addr->destipaddr) = *(unsigned int *)(addr->destipaddr) - offset;
				addr->ipchksum = 0;
				addr->ipchksum = cal_cksum((unsigned short *)addr, ((addr->vhl & 0xf) * 4));	

				if(addr->proto == PROTO_UDP) {
					struct uip_udpip_hdr *udp = (struct uip_udpip_hdr *)addr;
					udp->udpchksum = 0;
					udp->udpchksum = cal_udpchksum((unsigned short *)udp);
				} else if(addr->proto == PROTO_TCP) {
					struct uip_tcpip_hdr *tcp = (struct uip_tcpip_hdr *)addr;
					tcp->tcpchksum = 0;
					tcp->tcpchksum = cal_tcpchksum((unsigned short *)tcp);
				}
			}
#endif

			newlen = ntohs(*(unsigned short *)addr->len) + sizeof(struct espip_hdr); 
			*(unsigned short *)esp->ip.len = newlen;

			memcpy(esp->ip.ipid, addr->ipid, sizeof(u8_t) * 2);

			esp->ip.proto = IPPROTO_ESP;
			esp->ip.ipchksum = 0;

			memcpy(esp->ip.srcipaddr, addr->srcipaddr, sizeof(int));
			memcpy(esp->ip.destipaddr, addr->destipaddr, sizeof(int));

			newlen = (addr->vhl & 0xf) * 4;
			esp->ip.ipchksum = cal_cksum((unsigned short*)esp, newlen);

			//TODO ESP fake encapsulation
			esp->esp.spi = 0;
			esp->esp.seq = 0;
#if DEBUG_ENCRYPT
			printf("will encrypt outgoing data: ");
			show_buf(addr, (addr->len[0] << 8) + addr->len[1]);
#endif
			//encrypt the whole IP packet,here simple XOR the data
			newlen = encrypt(addr, (addr->len[0] << 8) + addr->len[1]);

			memcpy(buf + sizeof(struct espip_hdr), addr, newlen);
#if DEBUG_ENCRYPT
			printf("outgoing encrypted data: ");
			show_buf(buf, sizeof(struct espip_hdr) + newlen);
#endif
			sendto(sockfd, buf, sizeof(struct espip_hdr) + newlen, 0,  
						(struct sockaddr*)server, sizeof(struct sockaddr));
remove_packet:
			//remove packet from list
			list_del(packet);
			free(data->packet);
			free(data);
			continue;
		}
	}
}
int main() {
	
	pthread_create(&p_recv, NULL, readtun, NULL);
	pthread_create(&p_dispatch, NULL, dispatch_packet, NULL);
	pthread_create(&p_user_data, NULL, user_packet, NULL);
	pthread_create(&p_ipsec_data, NULL, ipsec_packet, NULL);

	while(1){
		sleep(1);
	}
	return 0;
}
