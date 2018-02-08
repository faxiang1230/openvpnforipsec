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
int parse_packet(struct list_head *list) {
	struct list_head *packet, *next;
	int ret = DISPATCH_NO_PACKET;
	//iterate 'tun' list and dispatch to user_data_list/ipsec_data_list
	list_for_each_safe(packet, next, list) {
		struct rcvpacket *data = list_entry(packet, struct rcvpacket, head);
		/* TODO detect packet type
		*/
		#if 0
		if(((struct ip_hdr*)data->packet)->proto == PROTO_ESP) { //check packet:tcp/udp or esp
			ret |= DISPATCH_ESP_PACKET;
			list_del(packet);
			list_add(packet, &ipsec_data_list);
			printf("get ESP packet\n");
		} else {
			ret |= DISPATCH_USER_PACKET;
			list_del(packet);
			list_add(packet, &user_data_list);
			printf("get normal packet\n");
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

	if((fd = open(TUN_PATH, O_RDWR)) < 0) {
		printf("open %s failed\n", TUN_PATH);
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
    /* Flags: IFF_TUN   - TUN device (no Ethernet headers) 
     *        IFF_TAP   - TAP device  
     *
     *        IFF_NO_PI - Do not provide packet information  
     */
	ifr.ifr_flags = IFF_TUN|IFF_NO_PI;
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
	char rcvbuff[1500], tunname[IFNAMSIZ];
	int nread;
	fd_set rfds;
	struct timeval tv;

	tunfd = tun_alloc(tunname);
	if (tunfd < 0) {
		exit(tunfd);
	} else {
		printf("open tun device:%s\n", tunname);
	}

	while(1) {
		struct rcvpacket *rcv;
		rcv = (struct rcvpacket *)malloc(sizeof(struct rcvpacket));
		INIT_LIST_HEAD(&rcv->head);

		FD_ZERO(&rfds);
		FD_SET(tunfd, &rfds);
		tv.tv_sec = DEF_INTERVAL_SEC;
		tv.tv_usec = DEF_INTERVAL_MSEC;

		int retval = select(tunfd + 1, &rfds, NULL, NULL, &tv);
		if (retval == -1)
			perror("select error\n");
		else if (retval) {
			dbglog("Data is available now.\n");
			if(FD_ISSET(tunfd, &rfds)) {
				nread = read(tunfd,rcvbuff, sizeof(rcvbuff));
				if (nread <=0) {
					printf("read from tun failed\n");
					continue;
				}
				rcv->packet = malloc(nread);

				#if DEBUG_PACKET
				rcv->len = nread;
				show_buf(rcvbuff + TUN_HEAD, nread);
				#endif

				memcpy(rcv->packet, rcvbuff, nread);
				dbglog("rcv from tun: %d bytes\n", nread);

				pthread_mutex_lock(&recv_mut);
				list_add_tail(&rcv->head, &tun);
				pthread_cond_signal(&recv_cond);
				pthread_mutex_unlock(&recv_mut);
			}
		} else {
			printf("No data within %d seconds.\n", DEF_INTERVAL_SEC);
		}
	}
}
static void *dispatch_packet(void *arg __attribute__((unused))) {
	while(1) {
		pthread_mutex_lock(&recv_mut);
		pthread_cond_wait(&recv_cond, &recv_mut);
		pthread_mutex_unlock(&recv_mut);
		int status = parse_packet(&tun);
	//	dbglog("parse packet, ret:%d\n", status);
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
	char buff[1500];
	int len = 0, ret = 0;
	struct sockaddr_in client;

	int rcvsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ESP);
	if(rcvsockfd < 0) {
		printf("create socket failed:%s\n", strerror(rcvsockfd));
		exit(-1);
	}

	while (1) {
		ret = recvfrom(rcvsockfd, buff, 1500, 0, (struct sockaddr*)&client, &len);
		if(ret > 0) {
			decrypt(buff + sizeof(struct espip_hdr), ret - sizeof(struct espip_hdr));
			int length = ntohs(*(unsigned short *)(((struct ip_hdr*)(buff + sizeof(struct espip_hdr)))->len));
			if(((struct ip_hdr*)buff)->proto == PROTO_ESP) {
#if DEBUG_PACKET
				show_buf(buff + sizeof(struct espip_hdr), length);
#endif
				ret = write(tunfd, buff + sizeof(struct espip_hdr), length);
				if (ret < length)
					printf("receive packet:%d bytes, write packet:%d bytes, failed:%d\n", length, ret, length - ret);
			}
		}
	}   
}
static void *user_packet(void *arg __attribute__((unused))) {
	int one = 1;
	unsigned int newlen = 0;
	struct sockaddr_in *server = NULL;
	struct list_head *packet,*next;
	char buf[1500];

	server = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	server->sin_family =AF_INET;
	//server->sin_port = htons(23456);
	server->sin_addr.s_addr = inet_addr(SERVER_IP);

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP|IPPROTO_UDP|IPPROTO_ICMP);
	if (sockfd < 0) {
		printf("create socket failed:%s\n", strerror(sockfd));
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
			struct uip_udpip_hdr *addr = data->packet + TUN_HEAD;

			if((addr->vhl >> 4) == IPV6_VERSION)
				goto remove_packet;

		#if DEBUG_PACKET
			printf("Get data from user:\n");
			dump_udp(data->packet + TUN_HEAD);
		#endif	
			//encapsulate ip packet with tunnel ESP mode
			//TODO

			struct espip_hdr *esp = malloc(sizeof(struct espip_hdr));
			memcpy(&esp->ip, addr, sizeof(struct ip_hdr));

			newlen = ntohs(*(unsigned short *)addr->len) + sizeof(struct espip_hdr); 
			*(unsigned short *)esp->ip.len = newlen;

			memcpy(esp->ip.ipid, addr->ipid, sizeof(u8_t) * 2);

			esp->ip.proto = IPPROTO_ESP;
			esp->ip.ipchksum = 0;

			int tmpaddr = inet_addr("10.0.0.160");
			memcpy(esp->ip.srcipaddr, &tmpaddr, sizeof(int));
			tmpaddr = inet_addr(SERVER_IP);
			memcpy(esp->ip.destipaddr, &tmpaddr, sizeof(int));
			
			newlen = (addr->vhl & 0xf) * 4;
			esp->ip.ipchksum = cal_cksum((unsigned short*)esp, newlen);

			//TODO ESP encapsulation
			esp->esp.spi = 0;
			esp->esp.seq = 0;
			//encrypt the whole IP packet,here simple XOR the data
			newlen = encrypt(addr, (addr->len[0] << 8) + addr->len[1]);

			memset(buf, 0, 1500);
			memcpy(buf, esp, sizeof(struct espip_hdr));
			//memcpy(buf + sizeof(struct espip_hdr), addr, (addr->len[0] << 8) + addr->len[1] );
			//newlen = sizeof(struct espip_hdr) + (addr->len[0] << 8) + addr->len[1];
			memcpy(buf + sizeof(struct espip_hdr), addr, newlen);
#if DEBUG_PACKET
			show_buf(buf, sizeof(struct espip_hdr) + newlen);
#endif
			sendto(sockfd, buf, sizeof(struct espip_hdr) + newlen, 0,  
						(struct sockaddr*)server, sizeof(struct sockaddr));
remove_packet:
			//remove packet from list
			list_del(packet);
			continue;
		}
	}
}
int main() {
	debuggerd_init();
	
	pthread_create(&p_recv, NULL, readtun, NULL);
	pthread_create(&p_dispatch, NULL, dispatch_packet, NULL);
	pthread_create(&p_user_data, NULL, user_packet, NULL);
	pthread_create(&p_ipsec_data, NULL, ipsec_packet, NULL);

	while(1){
		sleep(1);
	}
	return 0;
}
