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
int tunfd = 0,sockfd =0;
pthread_t readtun_thread,writetun_thread;
#define log(format, ...) do{if(1){printf((format), __VA_ARGS__);}}while(0)
#define MAX_CLIENTS 16
struct ip_map {
	struct in_addr phy_src;
	struct in_addr vir_src;
	struct in_addr vir_des;
	__be16 phy_sport;
};
struct ip_map *ip_map;
void init_ipmap() {
	ip_map = (struct ip_map*)malloc(sizeof(ip_map) * MAX_CLIENTS);
	if (NULL == ip_map) {
		printf("initial ip_map failed\n");
	}
	memset(ip_map, 0, sizeof(ip_map) * MAX_CLIENTS);
}
int find_ipmap(struct ip_map *ip) {
	int num = 0;
	for(num = 0; num < MAX_CLIENTS; num ++) {
		if(!strncmp(&ip_map[num].vir_src , &ip->vir_src, sizeof(struct in_addr)) && \
				!strncmp(&ip_map[num].vir_des,&ip->vir_des, sizeof(struct in_addr)))
			break;
	}
	if(num < MAX_CLIENTS)
		return num;
	else
		return -1;

}
int next_ipmap() {
	int num = 0;
	struct in_addr *null_addr = inet_addr("0.0.0.0");
	for(num = 0; num < MAX_CLIENTS; num ++) {
		if(!strncmp(&ip_map[num].phy_src,null_addr, sizeof(struct in_addr)))
			break;
	}
	if(num < MAX_CLIENTS)
		return num;
	else
		return -1;
}
int add_ipmap(struct ip_map *newip) {
	int index = next_ipmap();
	if (index > 0) {
		strncpy(&ip_map[index],newip,sizeof(struct ip_map));
		return index;
	}
	return -1;
}
int del_ipmap(struct ip_map *ip) {
	int index = find_ipmap(ip);
	if (index > 0) {
		memset(&ip_map[index],0,sizeof(struct ip_map));
		return index;
	}
	return -1;
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
	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
		printf("ioctl error:%s\n",strerror(err));
		close(fd);
		return err;
	}
	printf("open device:%s\n", ifr.ifr_ifrn.ifrn_name);
	strncpy(device, ifr.ifr_ifrn.ifrn_name, IFNAMSIZ);
	return fd;
}           
#if 0
static void *readtun(void *arg __attribute__((unused))) {
	char rcvbuff[1500];
	int nread;
	while(1) {
		nread = read(tunfd,rcvbuff, sizeof(rcvbuff));
		if (nread <=0) {
			printf("read from tun failed\n");
			continue;
		}
		printf("rcv from tun: %d bytes\n", nread);
		//encrypt(rcvbuff, nread, encbuff);
		write(sockfd, rcvbuff, nread);
	}
}
static void *writetun(void *arg __attribute__((unused))) {
	char linkbuff[1500];
	int nread = 0;
	while(1) {
		nread = read(sockfd,linkbuff, sizeof(linkbuff));
		if(nread < 0) {
			continue;
		}
		//decrypt(nread,);
		//verify(ip);
		printf("rcv from link: %d bytes\n", nread);
		write(tunfd,linkbuff,nread);
	}
}
#endif
#define FD_SETSIZE 16
int main() {
	char tun[IFNAMSIZ];
	char linkbuff[1500];
	int nread = 0;
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
	server->sin_addr.s_addr = inet_addr("10.0.0.160");
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(bind(sockfd, (struct sockaddr*)server, sizeof(*server))) {
		printf("bind failed\n");
	}
	listen(sockfd, SOMAXCONN);

	int clientfd;
	struct sockaddr_in *client = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	int client_size = sizeof(*client);
	int child_pid = 0;
	char *buf = (char*)malloc(1000);
	int bytes;
#if 0
	clientfd = accept(sockfd, (struct sockaddr_in*)client, &client_size);
	printf("%s\n", strerror(errno));
	while(1) {
		nread = read(clientfd, (void *)linkbuff, 1500);
		printf("read from:%d,%d :%d\n", sockfd,clientfd, nread);
		write(clientfd, linkbuff, nread);
		sleep(5);
	}
#else
	while(1) {
		int status;
		fd_set reads;
		struct timeval tv;

		FD_ZERO(&reads);
		FD_SET(sockfd, &reads);
		tv.tv_sec = 0;
		tv.tv_usec = 0;

		status = select(sockfd + 1, &reads, NULL, NULL, &tv);
		if(status <= 0)
			continue;
		clientfd = accept(sockfd, (struct sockaddr_in*)client, &client_size);
		if((child_pid = fork()) == 0) {
			while(1) {
				nread = read(clientfd, linkbuff, sizeof(linkbuff));
				printf("read :%d bytes\n", nread);
			}
		} else {
			close(clientfd);
		}
		//decrypt
		//write(clientfd, linkbuff, sizeof(linkbuff));
		//write(tunfd, linkbuff, sizeof(linkbuff));
		sleep(1);
	}
#endif

	//pthread_create(&readtun_thread, NULL, readtun, NULL);
	//pthread_create(&writetun_thread, NULL, writetun, NULL);
	while(1){sleep(1);}
	printf("tun is over\n");
	return 0;
}

