#include <stdio.h>
#define CRYPT_SEED 0xaa;
void show_buf(void *addr, int len) {
    int num = 0;
    for(num = 0; num < len; num++) {
        printf("%c ", ((unsigned char *)addr)[num]);
    }   
	printf("\n");
}
int encrypt(void *addr, int len) {
    int num = 0;
    for ( ; num < len; num++) {
        *(unsigned char *)addr ^= CRYPT_SEED;
        addr++;
    }   
}
int decrypt(void *addr, int len) {
    int num = 0;
    for ( ; num < len; num++) {
        *(unsigned char *)addr ^= CRYPT_SEED;
        addr++;
    }   
}
void main() {
	char buf[4] = {'a','b','c','d'};
	int num = 0;
	int len = 4;
	encrypt(buf, 4);
	show_buf(buf, 4);
	decrypt(buf, 4);
	show_buf(buf, 4);
}
