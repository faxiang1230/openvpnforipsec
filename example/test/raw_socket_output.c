/*
 * Work as normal app which its data will be encrypted
 * why create this example?
 * Keep IP packet as small as possible;
 * just a demo,no splice function
 */
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <errno.h>

int main() {
	int sockfd = 0, ret = 0, len = 0;
	char w_data[256] = {0x45,0x00 ,0x01,0x00 ,0x27 ,0xa1 ,0x40 ,0x00 ,0x3f ,0x32 ,0x46 ,0xe1 ,0xc0 ,0xa8 ,0x01 ,0x02 ,0x0a ,0x00 ,0x00 ,0xa0 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x45 ,0x00 ,0x00 ,0x27 ,0x27 ,0xa1 ,0x40 ,0x00 ,0x40 ,0x11 ,0x00 ,0x00 ,0xc0 ,0xa8 ,0x01 ,0x0c ,0xc0 ,0xa8 ,0x01 ,0x0a ,0x5b ,0xa0 ,0xd7 ,0x66 ,0x00 ,0x13 ,0x01 ,0x71 ,0x61 ,0x61 ,0x61 ,0x61 ,0x61, 0x61 ,0x61 ,0x61 ,0x61,0x61,0x61};
	int one = 1;
	struct sockaddr_in *server = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	struct sockaddr_in client;
	memset(&client, 0, sizeof(struct sockaddr_in));
	server->sin_family =AF_INET;
	server->sin_port = htons(23456);
	server->sin_addr.s_addr = inet_addr("10.0.0.160");
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP|IPPROTO_UDP|IPPROTO_ICMP);
	if(sockfd < 0)
		printf("create socket failed:%s\n", strerror(sockfd));
	setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
		ret = sendto(sockfd, w_data, 256, 0, (struct sockaddr*)server, sizeof(struct sockaddr));	
		if (ret > 0)
			printf("send to server:%d\n", ret);
		else
			printf("error:%s\n",strerror(errno));
	sleep(1);
	return 0;
}
