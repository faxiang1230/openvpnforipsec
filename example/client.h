#ifndef IPSECEXAMPLE_CLIENT
#define IPSECEXAMPLE_CLIENT
#include "list.h"
#include "log.h"
#include <pthread.h>

#define DEBUG 1

#define DISPATCH_NO_PACKET 0
#define DISPATCH_USER_PACKET 1
#define DISPATCH_ESP_PACKET 2


struct rcvpacket {
	struct list_head head;
	void *packet;
#if DEBUG
	size_t len;
#endif
};

static pthread_t p_recv,p_dispatch,p_user_data,p_ipsec_data;
pthread_mutex_t recv_mut = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t recv_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t user_mut = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t user_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t ipsec_mut = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t ipsec_cond = PTHREAD_COND_INITIALIZER;

/*
  receive from tun device(userdata packet and
  ipsec packet)
*/
static LIST_HEAD(tun);
static LIST_HEAD(user_data_list);
static LIST_HEAD(ipsec_data_list);

static int tunfd = 0,sockfd =0;

int tun_alloc(char *device);
static void *readtun(void *arg __attribute__((unused)));
static void *dispatch_packet(void *arg __attribute__((unused)));
int parse_packet(struct list_head *list); 

#endif //IPSECEXAMPLE_CLIENT
