/*************************************************************************
  > File Name: listen-ping.c
  > Author: wangjx
  > Mail: wangjianxing5210@163.com 
  > Created Time: Sunday, February 25, 2018 PM10:45:41 HKT
 ************************************************************************/

#include<stdio.h>
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
int main() {
	char r_data[1500];
	int ret = 0, len = 0, sockfd = 0;
	struct sockaddr_in *server = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	struct sockaddr_in client;

	len = sizeof(struct sockaddr);

	server->sin_family =AF_INET;
	//server->sin_port = htons(23456);
	server->sin_addr.s_addr = htonl(INADDR_ANY);

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sockfd < 0) {
		printf("error  socket:%s\n", strerror(errno));
		exit(-1);
	}

	while(1) {
		memset(r_data, 0, 1500);
		ret = recvfrom(sockfd, r_data, 1500, 0, (struct sockaddr*)&client, &len);
		if (ret > 0)
			show_buf(r_data, ret);
	}
}
