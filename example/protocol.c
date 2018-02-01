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
	return 0;
}
int verifyip(void *addr) {
	struct uip_udpip_hdr *hdr = addr;
	/* Now only accept IPV4 */
	if((hdr->vhl >> 4) != IPV4_VERSION)
		return -1;
	if(chksum(addr, IPV4_VERSION)) {
		dbglog("ip packet chksum failed\n");
		return -1;
	}
}
int verifyudp(void *iphdr) {
	struct uip_udpip_hdr *hdr = iphdr;
	unsigned int sum = 0,len,num;
	struct pseudo_udphdr f;
	unsigned short *addr = NULL;
#if 0
	f.srcipaddr[0] = (unsigned short)htons(hdr->srcipaddr[0]);
	f.srcipaddr[1] = (unsigned short)htons(hdr->srcipaddr[1]);
	f.destipaddr[0] = (unsigned short)htons(hdr->destipaddr[0]);
	f.destipaddr[1] = (unsigned short)htons(hdr->destipaddr[1]);
#endif
	memcpy(&f,&hdr->srcipaddr, 8);
	f.pad = 0;
	f.proto = 17;
#if 0
	f.udplen = (unsigned short)htons(hdr->udplen);
#endif
	memcpy(&f.udplen, &hdr->udplen, 2);
	len = sizeof(struct pseudo_udphdr);
	addr = &f;
	#if 0
	dbglog("dummpy udphdr length:%d\n", len);
    for(num = 0; num < len; num++) {
        dbglog("%02x ", ((unsigned char *)addr)[num]);
    }   
	dbglog("\n");
	#endif
	while(len > 0) {
		sum += htons((unsigned short)((*addr)));
		addr++;
	//	dbglog("%02x ", sum);
		len -= 2;
	}
	dbglog("\n");

	unsigned short chksum = (unsigned short)hdr->udpchksum;
	hdr->udpchksum = 0;
	addr = iphdr + ((hdr->vhl & 0xf) * 4); 
	len = (unsigned short)htons(hdr->udplen);
#if 0
	dbglog("udp header and data:%p-%p:%d \n", iphdr, addr, len);
    for(num = 0; num < len; num++) {
        dbglog("%02x ", htons(addr[num]));
    }   
	dbglog("\n");
	dbglog("last sum:%02x\n", sum);
#endif
	while(len > 1) {
	//	dbglog("data:%02x\n", (unsigned short)(htons(*addr)));
		sum += (unsigned short)(htons(*addr));
		addr++;
	//	dbglog("sum:%02x \n", sum);
		len -= 2;
	}
	if (len) {
		//dbglog("%x\n", htons((*(unsigned char*)addr)));
		sum += htons((*(unsigned char*)addr)); 
	}
	//dbglog("\n");
	if(sum > 65535)
		sum = (sum >> 16) + (sum & 0xffff);
	//dbglog("the last:%02x \n", sum);
	hdr->udpchksum = chksum;
	dbglog("%04x %04x\n",htons(hdr->udpchksum), (unsigned short)~sum);
	if(htons(hdr->udpchksum) == ((unsigned short)~sum))
		return 0;
	return -1;
}
void show_udpip(void *addr) {
	int ret = verifyip(addr);
	if (ret == -1)
		return; 
	ret = verifyudp(addr);
	if (ret == -1) {
		dbglog("udp chksum failed\n");
		return;
	}
	struct uip_udpip_hdr *hdr = addr;
	dbglog("IP header info:\nversion:%u header length:%u packet length:%u\n",\
	(hdr->vhl >> 4), (hdr->vhl & 0xf),((hdr->len[0] << 8) + hdr->len[1]));
}
