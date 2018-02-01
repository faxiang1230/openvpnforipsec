CC:=gcc
CFLAGS:=-g
LDFLAGS:=-lpthread
COMMON_FILES=log.c debugger.c protocol.c

all:client-d server-d example-c example-s

client-d:client-daemon.c $(COMMON_FILES)
	$(CC) $^ -o $@ $(LDFLAGS) $(CFLAGS)

server-d:server-daemon.c $(COMMON_FILES)
	$(CC) $^ -o $@ $(LDFLAGS) $(CFLAGS)

example-c:client-example.c
	$(CC) $^ -o $@ $(LDFLAGS) $(CFLAGS)
example-s:server-example.c
	$(CC) $^ -o $@ $(LDFLAGS) $(CFLAGS)

.PHONY:clean
clean:
	rm -rf client-d server-d example-c example-s *.o
