#include <stdio.h>
#include <unistd.h>

typedef struct {
	int srcIp;
	int dstIp;
	short udp_len;
	char rsv;
	char protocol;
	unsigned short src_port;
	unsigned short dst_port;
	unsigned short len;
	unsigned short check_sum;
	char data[11];
} UDPHDR;

unsigned short check_sum1(unsigned short *a, int len);
unsigned short check_sum2(unsigned short *a, int len);

int main()
{
	short b = 0;
	UDPHDR udphdr = {0};

	udphdr.srcIp = inet_addr("10.0.0.160");
	udphdr.dstIp = inet_addr("10.0.0.161");
	udphdr.udp_len = htons(19);
	udphdr.protocol = 17;
	udphdr.rsv = 0;
	udphdr.src_port = htons(50094);
	udphdr.dst_port = htons(23456);
	udphdr.len = htons(19);
	udphdr.check_sum = 0;
	udphdr.data[0] = 0x48;
	udphdr.data[1] = 0x65;
	udphdr.data[2] = 0x6c;
	udphdr.data[3] = 0x6c;
	udphdr.data[4] = 0x6f;
	udphdr.data[5] = 0x20;
	udphdr.data[6] = 0x49;
	udphdr.data[7] = 0x50;
	udphdr.data[8] = 0x53;
	udphdr.data[9] = 0x65;
	udphdr.data[10] = 0x63;

	b = check_sum1((short *)&udphdr, sizeof(UDPHDR));
	printf("[test ...] b = %04x\n", htons(b & 0xffff));

	b = check_sum2((short *)&udphdr, sizeof(UDPHDR));
	printf("[test ...] b = %04x\n", htons(b & 0xffff));

	return 0;
}

unsigned short check_sum1(unsigned short *a, int len) {
	unsigned int sum = 0;
	while(len > 1) {
		sum += (unsigned short)(~(*a));
		a++;
		if(sum > 65535)
			sum = (sum >> 16) + (sum & 0xffff);
		len-=2;
	}
	if (len) {
		sum += ((*(unsigned char*)a) << 8);
	}
	return (unsigned short)sum;
}
unsigned short check_sum2(unsigned short *a, int len)
{
	unsigned int sum = 0;

	while (len > 1) {
		sum += *a++;
		len -= 2;
	}

	if (len) {
		sum += *(unsigned char *)a;
	}

	while (sum >> 16) {
		sum = (sum >> 16) + (sum & 0xffff);
	}

	return (unsigned short)(~sum);
}
