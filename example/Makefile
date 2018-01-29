CC:=gcc
CFLAGS:=-g
LDFLAGS:=-lpthread
COMMON_FILES=log.c debugger.c

all:client server

client:client.c $(COMMON_FILES)
	$(CC) $^ -o $@ $(LDFLAGS) $(CFLAGS)

server:server.c $(COMMON_FILES)
	$(CC) $^ -o $@ $(LDFLAGS) $(CFLAGS)

.distclean:clean
clean:
	rm client server *.o
