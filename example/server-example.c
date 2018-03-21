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
int main() {
	char r_data[1500];
	int ret = 0, len = 0, sockfd = 0;
	struct sockaddr_in *server = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	struct sockaddr_in client;

	len = sizeof(struct sockaddr);

	server->sin_family =AF_INET;
	server->sin_port = htons(23456);
	server->sin_addr.s_addr = htonl(INADDR_ANY);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if(bind(sockfd, (struct sockaddr*)server, sizeof(struct sockaddr_in))) {
		printf("bind failed\n");
	}

	while(1) {
		memset(r_data, 0, 1500);
		ret = recvfrom(sockfd, r_data, 1500, 0, (struct sockaddr*)&client, &len);
		if (ret > 0)
			printf("recv from client:%s\n", r_data);
		sprintf(&r_data[ret], " I'm Server\n");
		ret = sendto(sockfd, r_data, 128 , 0, (struct sockaddr*)&client, len);	
		if (ret > 0)
			printf("send to client:%s\n", r_data);
		else {
			printf("send data to %d:%u failed,error:%s\n", inet_ntoa(client.sin_addr),
			 client.sin_port, strerror(errno));
		}
//		sleep(1);
	}
	return 0;
}

