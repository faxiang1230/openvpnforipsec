#ifndef IPSECEXAMPLE_PROTOCOL_H
#define IPSECEXAMPLE_PROTOCOL_H
#include <inttypes.h>

#define TUNNEL_MODE 1

#define USERDATA 1
#define ESPDATA 2

#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ESP 50

#define IPV4_VERSION 4
#define IPV6_VERSION 6
typedef uint8_t u8_t;
typedef uint16_t u16_t;

struct ip_hdr {
  /* IPv4 header. */
  u8_t vhl,
    tos,
    len[2],
    ipid[2],
    ipoffset[2],
    ttl,
    proto;
  u16_t ipchksum;
  u16_t srcipaddr[2],
    destipaddr[2];
};
struct esp_hdr {
	uint32_t spi;
	uint32_t seq; 
};
struct espip_hdr {
	struct ip_hdr ip;
	struct esp_hdr esp;
};
/* The UDP and IP headers. */
struct uip_udpip_hdr {
#if UIP_CONF_IPV6
  /* IPv6 header. */
  u8_t vtc, 
    tcf; 
  u16_t flow;
  u8_t len[2];
  u8_t proto, ttl; 
  uip_ip6addr_t srcipaddr, destipaddr;
#else /* UIP_CONF_IPV6 */
  /* IP header. */
  u8_t vhl, 
    tos, 
    len[2],
    ipid[2],
    ipoffset[2],
    ttl, 
    proto;
  u16_t ipchksum;
  u16_t srcipaddr[2],
    destipaddr[2];
#endif /* UIP_CONF_IPV6 */
  
  /* UDP header. */
  u16_t srcport,
    destport;
  u16_t udplen;
  u16_t udpchksum;
};
struct pseudo_udphdr{
	u16_t srcipaddr[2],
		destipaddr[2];
	u8_t pad, proto;
	u16_t udplen;
};
/*
 *  Normal User Data
 * | IP header | TCP/UDP | Data |
 * after encapsulation esp
 * | IP header | ESP header | encrypted data | end |
 * 'encrypted data' is the data which
 * 'Normal User Data' is encrypted
 */
int verifypacket(void *header);
int isESP(void *header);
int encapsulate_esp(void *header, int len);
void *decapsulate_esp(void *header);
void show_udpip(void *);

#endif //IPSECEXAMPLE_PROTOCOL_H
