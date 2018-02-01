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

int main() {
	int sockfd = 0, ret = 0, len = 0;
	char w_data[16] = "Hello IPSec", r_data[1500];

	struct sockaddr_in *server = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	struct sockaddr_in client;
	memset(&client, 0, sizeof(struct sockaddr_in));
	server->sin_family =AF_INET;
	server->sin_port = htons(23456);
	server->sin_addr.s_addr = inet_addr("10.8.0.161");
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0)
		printf("create socket failed:%s\n", strerror(sockfd));
	
	while(1){
		ret = sendto(sockfd, w_data, strlen(w_data), 0, (struct sockaddr*)server, sizeof(struct sockaddr));	
		if (ret > 0)
			printf("send to server:%s\n", w_data);
		ret = recvfrom(sockfd, r_data, 1500, 0, (struct sockaddr*)&client, &len);
		if (ret > 0)
			printf("recv from server:%s\n", r_data);
		else
			printf("recv failed:%d\n", ret);
		memset(r_data, 0, 1500);
		sleep(1);
	}
	return 0;
}
