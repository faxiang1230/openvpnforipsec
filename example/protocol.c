#include "protocol.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

int encapsulate_esp(void *header, int len) {
	
}
void *decapsulate_esp(void *header) {

}
int verifypacket(void *header) {
	return 0;
}
int isESP(void *header) {
	return 0;
}
int chksum(unsigned short *addr, int type) {
	if(type == IPV4_VERSION) {
		int len = (((struct uip_udpip_hdr *)addr)->vhl & 0xf) * 4;
		unsigned int sum = 0;
		while(len > 0) {
			sum += (unsigned short)(~(*addr));
			addr++;
			if(sum > 65535)
            	sum = (sum >> 16) + (sum & 0xffff);
			len -= 2;
		}
		if ((sum & 0xffff) == 0xffff)
			return 0;
		else
			return -1;
	}
	return -1;
}
int verify_ip(void *addr) {
	struct ip_hdr *hdr = addr;
	/* Now only accept IPV4 */
	if((hdr->vhl >> 4) != IPV4_VERSION) {
		printf("Not support ipv6\n");
		return -1;
	}
	if(chksum(addr, IPV4_VERSION)) {
		printf("ip packet chksum failed\n");
		return -1;
	}
	return 0;
}
int verify_udp(void *iphdr) {
	struct uip_udpip_hdr *hdr = iphdr;
	unsigned int sum = 0,len, num;
	struct pseudo_udphdr f;
	unsigned short *addr = NULL;

	memcpy(&f, &hdr->srcipaddr, 8);
	f.pad = 0;
	f.proto = PROTO_UDP;

	memcpy(&f.udplen, &hdr->udplen, sizeof(u16_t));

	len = sizeof(struct pseudo_udphdr);
	addr = (unsigned short *)&f;

	while (len > 0) {
		sum += *addr;
		addr++;
		len -= 2;
	}
	dbglog("\n");

	unsigned short chksum = (unsigned short)hdr->udpchksum;
	hdr->udpchksum = 0;
	addr = iphdr + ((hdr->vhl & 0xf) * 4); 
	len = ntohs(hdr->udplen);
	while(len > 1) {
		sum += *addr;
		addr++;
		len -= 2;
	}
	if (len) {
		sum += *(unsigned char*)addr; 
	}
	while (sum >> 16)
		sum = (sum >> 16) + (sum & 0xffff);
	hdr->udpchksum = chksum;
	dbglog("verify_udp chksum %04x %04x\n",hdr->udpchksum, (unsigned short)~sum);
	if(hdr->udpchksum == ((unsigned short)~sum))
		return 0;
	return -1;
}
void dump_udp(void *addr) {
	if (verify_ip(addr))
		return;

	if (verify_udp(addr));
		return;

	struct uip_udpip_hdr *hdr = addr;
	printf("IP header info:\nversion:%u header length:%u packet length:%u\n",\
	(hdr->vhl >> 4), (hdr->vhl & 0xf),((hdr->len[0] << 8) + hdr->len[1]));
}
unsigned short cal_cksum(unsigned short* head, int len) {
	unsigned int sum = 0;
	while(len > 1) {
		sum += *head++;
		len -= 2;
	}
	if (len) {
		sum += *(unsigned char *)head;
	}

	while (sum >> 16) {
		sum = (sum >> 16) + (sum & 0xffff);
	}

	return (unsigned short)(~sum);
}
int encrypt(void *addr, int len) {
	int num = 0;
	for ( ; num < len; num++) {
		*(unsigned char *)addr ^= CRYPT_SEED;
		addr++;
	}
	return len;
}
int decrypt(void *addr, int len) {
	int num = 0;
	for ( ; num < len; num++) {
		*(unsigned char *)addr ^= CRYPT_SEED;
		addr++;
	}
	return len;
}
