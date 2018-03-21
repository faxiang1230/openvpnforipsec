#ifndef IPSECEXAMPLE_PROTOCOL_H
#define IPSECEXAMPLE_PROTOCOL_H
#include <inttypes.h>

//#define DEBUG_PACKET 1

/*
 * Protocol info prepended to the packets (when IFF_NO_PI is not set)
 * struct tun_pi {
 *	__u16  flags;
 *	__be16 proto;
 * };
 * Don't prepend PI,so don't define USE_PI
 */
#ifdef USE_PI
/* When I read tun data,always '00 00 08 00' ahead of IP packet */
/* When set TUN_NO_PI flag,no prepend data */
#define TUN_HEAD 4
#else
#define TUN_HEAD 0
#endif

/* encapsulate mode */
#define TUNNEL_MODE 1
//#define TRANSPORT_MODE 1


/* 
 * obsolete 
 * client daemon receive 2 kinds of packet:from application
 * without ESP capsulation,from server with ESP capsulation
 */
#define USERDATA 1
#define ESPDATA 2

/* 8bit protocol value,see /etc/protocols */
#define PROTO_TCP 6
#define PROTO_ICMP 1
#define PROTO_UDP 17
#define PROTO_ESP 50

/* IP header 4bit protocol value */
#define IPV4_VERSION 4
#define IPV6_VERSION 6

#define CRYPT_SEED 0xaa
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
/* The TCP and IP headers. */
struct uip_tcpip_hdr {
#if UIP_CONF_IPV6
  /* IPv6 header. */
  u8_t vtc, 
    tcflow;
  u16_t flow;
  u8_t len[2];
  u8_t proto, ttl; 
  uip_ip6addr_t srcipaddr, destipaddr;
#else /* UIP_CONF_IPV6 */
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
#endif /* UIP_CONF_IPV6 */
  
  /* TCP header. */
  u16_t srcport,
    destport;
  u8_t seqno[4],
    ackno[4],
    tcpoffset,
    flags,
    wnd[2];
  u16_t tcpchksum;
  u8_t urgp[2];
  u8_t optdata[4];
};
struct pseudo_tcphdr{
	u16_t srcipaddr[2],
		destipaddr[2];
	u8_t pad, proto;
	u16_t tcplen;
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
void dump_udp(void *);
unsigned short cal_cksum(unsigned short* head, int len);
unsigned short cal_udpchksum(unsigned short *iphdr);
unsigned short cal_tcpchksum(unsigned short *iphdr);
int encrypt(void *addr, int len);
int decrypt(void *addr, int len);

#endif //IPSECEXAMPLE_PROTOCOL_H
