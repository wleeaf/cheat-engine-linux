#include <stdio.h>
#include <unistd.h>
/* A stand-in game for the README screenshot: a few values to find and edit. */
volatile int health = 100, ammo = 30, gold = 1250;
volatile float speed = 1.5f;
int main(void) {
    printf("%p %p %p %p\n", (void*)&health, (void*)&ammo, (void*)&gold, (void*)&speed);
    fflush(stdout);
    for (;;) sleep(1);
}
