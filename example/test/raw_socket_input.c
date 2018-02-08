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
#include "../log.h"
int main() {
	char buff[1500];
	int sockfd = 0,ret = 0, len = 0;
	struct sockaddr_in client;
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ESP);
	int one = 1;
	if(sockfd < 0)
		printf("create socket failed:%s\n", strerror(sockfd));
#if 0
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){  //设置套接字行为，此处设置套接字不添加IP首部  
        printf("setsockopt failed!\n");  
        return -1;
    }  
#endif
	while(1){
		ret = recvfrom(sockfd, buff, 1500, 0, (struct sockaddr*)&client, &len);
		if(ret > 0) {
		printf("recive\n");
		show_buf(buff, ret);
		}
	}
	return 0;
}
