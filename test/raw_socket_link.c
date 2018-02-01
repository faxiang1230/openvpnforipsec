#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<unistd.h>
#include<linux/if_ether.h>

unsigned short int cksum(char buffer[], int size){  //校验函数
	unsigned long sum = 0;
	unsigned short int answer;
	unsigned short int *temp;
	temp = (short int *)buffer;
	for( ; temp<buffer+size; temp+=1)
		sum += *temp;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return answer;
}

int main(){
	unsigned char buffer[1024];
	int i;
	//  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);//不知为啥，无法设置原始套接字在网络层抓IP数据报
	int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP)); //此处，利用原始套接字在数据链路层抓取MAC帧，去掉
	if(sockfd < 0){                                            //14个字节的MAC帧首部即可
		printf("create sock failed\n");
		return -1;
	}    
	int n = recvfrom(sockfd, buffer, 1024, 0, NULL, NULL); //接收MAC帧

	printf("receive %d bytes\n", n);
	for(i=14; i<n; i++){      //去掉MAC帧首部，直接输出IP数据报每个字节的数据
		if((i-14) % 16 == 0)
			printf("\n");
		printf("%d ",buffer[i]);
	}
	printf("\n");
	printf("ipcksum: %d\n", cksum(buffer+14, 20)); //此处再次校验时，应当输出0
	return 0;
}
