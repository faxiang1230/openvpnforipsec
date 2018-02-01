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
#include "client.h"
#include "log.h"
#include "protocol.h"
void show_buf(void *addr, int len) {
	int num = 0;
	dbglog("show buf:%d\n", len);
	for(num = 0; num < len; num++) {
		printf("%02x ", ((unsigned char *)addr)[num]);
	}
	dbglog("\n");
}
int parse_packet(struct list_head *list) {
	struct list_head *packet, *next;
	int ret = DISPATCH_NO_PACKET;
	//iterate 'tun' list and dispatch to user_data_list/ipsec_data_list
	list_for_each_safe(packet, next, list) {
		struct rcvpacket *data = list_entry(packet, struct rcvpacket, head);
		/* TODO detect packet type
		*/
		#if 0
		if(((char*)data->packet)[] == ESP) { //check packet:tcp/udp or esp
			ret |= DISPATCH_ESP_PACKET;
			list_del(packet);
			list_add(packet, ipsec_data_list);
		} else {
			ret |= DISPATCH_USER_PACKET;
			list_del(packet);
			list_add(packet, user_data_list);
		}
		#else
		ret |= DISPATCH_USER_PACKET;
		list_del(packet);
		list_add(packet, &user_data_list);
		#endif
	}
	return ret;
}
int tun_alloc(char *device)
{
	struct ifreq ifr;
	int fd, err;

	if((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		printf("open /dev/net/tun failed\n");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN;
	//ifr.ifr_flags = IFF_TAP;  //tap
	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
		printf("ioctl error:%s\n",strerror(err));
		close(fd);
		return err;
	}
	strncpy(device, ifr.ifr_ifrn.ifrn_name, IFNAMSIZ);
	return fd;
}           
static void *readtun(void *arg __attribute__((unused))) {
	char rcvbuff[1500];
	int nread;
	fd_set rfds;
	struct timeval tv;
	while(1) {
		struct rcvpacket *rcv;
		rcv = (struct rcvpacket *)malloc(sizeof(struct rcvpacket));
		INIT_LIST_HEAD(&rcv->head);
		FD_ZERO(&rfds);
		FD_SET(tunfd, &rfds);
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		int retval = select(tunfd+1, &rfds, NULL, NULL, &tv);
		if (retval == -1)
			perror("select()");
		else if (retval) {
			dbglog("Data is available now.\n");
			if(FD_ISSET(tunfd, &rfds)) {
				nread = read(tunfd,rcvbuff, sizeof(rcvbuff));
				if (nread <=0) {
					printf("read from tun failed\n");
					continue;
				}
				rcv->packet = malloc(nread);
				#if DEBUG
				rcv->len = nread;
				show_buf(rcvbuff + TUN_HEAD, nread);
				//show_udpip(rcvbuff + TUN_HEAD);
				#endif
				memcpy(rcv->packet, rcvbuff, nread);

				dbglog("rcv from tun: %d bytes\n", nread);

				pthread_mutex_lock(&recv_mut);
				list_add_tail(&rcv->head, &tun);
				pthread_cond_signal(&recv_cond);
				pthread_mutex_unlock(&recv_mut);
			}
		} else
			printf("No data within five seconds.\n");
	}
}
static void *dispatch_packet(void *arg __attribute__((unused))) {
	while(1) {
		pthread_mutex_lock(&recv_mut);
		pthread_cond_wait(&recv_cond, &recv_mut);
		pthread_mutex_unlock(&recv_mut);
		int status = parse_packet(&tun);
		dbglog("parse packet, ret:%d\n", status);
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
	pthread_mutex_lock(&ipsec_mut);
	pthread_cond_wait(&ipsec_cond, &ipsec_mut);
	pthread_mutex_unlock(&ipsec_mut);
	
	struct list_head *packet,*next;
	//iterate 'tun' list and dispatch to user_data_list/ipsec_data_list
	list_for_each_safe(packet, next, &user_data_list) {
		struct rcvpacket *data = list_entry(packet, struct rcvpacket, head);
		//decapsulate tunnel ESP mode ip packet
		//TODO
#if 0
		int written = write(tunfd, ip_buf, length);
		free(data);
#endif
	}
}
static void *user_packet(void *arg __attribute__((unused))) {
	while(1) {
		pthread_mutex_lock(&user_mut);
		pthread_cond_wait(&user_cond, &user_mut);
		pthread_mutex_unlock(&user_mut);

		dbglog("deal with user data\n");
		struct list_head *packet,*next;
		//iterate 'tun' list and dispatch to user_data_list/ipsec_data_list
		list_for_each_safe(packet, next, &user_data_list) {
			struct rcvpacket *data = list_entry(packet, struct rcvpacket, head);
			struct uip_udpip_hdr *addr = data->packet + TUN_HEAD;
			if((addr->vhl >> 4) == IPV6_VERSION)
				goto remove_packet;
			//encapsulate ip packet with tunnel ESP mode
			//TODO
		#if DEBUG
			//show_udpip(data->packet + TUN_HEAD);	
		#endif	
			struct espip_hdr *esp = malloc(sizeof(struct espip_hdr));
			memcpy(&esp->ip, addr, sizeof(struct ip_hdr));
			unsigned int newlen = (addr->len[0] << 8) + addr->len[1] + sizeof(struct espip_hdr); 
			esp->ip.len[0] = (u8_t)(newlen >> 8);
			esp->ip.len[1] = (u8_t)(newlen & 0xff);
			newlen = (addr->ipid[0] << 8) + addr->ipid[1] + 10;
			esp->ip.ipid[0] =(u8_t)(newlen >> 8);
			esp->ip.len[1] = (u8_t)(newlen & 0xff);	
			esp->ip.proto = 50;
			esp->ip.ipchksum = 0;
			int tmpaddr = inet_addr("10.0.0.160");
			memcpy(esp->ip.srcipaddr, &tmpaddr, sizeof(int));
			tmpaddr = inet_addr("10.0.0.161");
			memcpy(esp->ip.destipaddr, &tmpaddr, sizeof(int));
			
			//printf("esp header:\n");
			//show_buf(esp, 20);
			newlen = (addr->vhl & 0xf) * 4;
			unsigned int sum = 0;
			unsigned char * a = esp;
			while (newlen > 1) {
				sum += (*a << 8)+*(a+1);
				a += 2;
				newlen -= 2;
			}

			if (newlen) {
				sum += *(unsigned char *)a;
			}   

			while (sum >> 16) {
				sum = (sum >> 16) + (sum & 0xffff);
			}
			esp->ip.ipchksum = htons((unsigned short)~sum);
			show_buf(esp, 20);
			esp->esp.spi = 0;
			esp->esp.seq = 0;

			struct sockaddr_in *server = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
			server->sin_family =AF_INET;
			server->sin_port = htons(23456);
			server->sin_addr.s_addr = inet_addr("10.0.0.161");
			char buf[1024];
			memcpy(buf, esp, sizeof(struct espip_hdr));
			memcpy(buf + sizeof(struct espip_hdr), addr, (addr->len[0] << 8) + addr->len[1] );
			show_buf(buf, sizeof(sizeof(struct espip_hdr)) + (addr->len[0] << 8) + addr->len[1]);
			sendto(sockfd, buf, 1024, 0,  (struct sockaddr*)server, sizeof(struct sockaddr));
			//int written = write(sockfd, data->packet, data->len);
			//printf("write raw data:%d\n", written);
			//free(data->packet);
remove_packet:
			//remove packet from list
			continue;
		}
	}
}
int main() {
	debuggerd_init();
	char tun[IFNAMSIZ];
	tunfd = tun_alloc(tun);
	if (tunfd < 0) {
		printf("open tun failed,exit\n");
		exit(tunfd);
	} else {
		printf("open tun device:%s\n", tun);
	}

	struct sockaddr_in *server = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	server->sin_family =AF_INET;
	server->sin_port = htons(23456);
	server->sin_addr.s_addr = inet_addr("10.0.0.161");
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP|IPPROTO_UDP|IPPROTO_ICMP);
	int one = 1;
	if(sockfd < 0)
		printf("create socket failed:%s\n", strerror(sockfd));
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){  //设置套接字行为，此处设置套接字不添加IP首部  
        printf("setsockopt failed!\n");  
        return -1;
    }  
	
	pthread_create(&p_recv, NULL, readtun, NULL);
	pthread_create(&p_dispatch, NULL, dispatch_packet, NULL);
	pthread_create(&p_user_data, NULL, user_packet, NULL);
	pthread_create(&p_ipsec_data, NULL, ipsec_packet, NULL);

	while(1){
		sleep(1);
	}
	return 0;
}
