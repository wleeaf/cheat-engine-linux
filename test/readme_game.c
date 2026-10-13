#include <stdio.h>
#include <string.h>
#include <unistd.h>
/* A stand-in game for the README screenshot and the MCP gate: a few values to
   find and edit. With --damage, health drops by one every 100 ms (refilling at
   zero), so there is code that writes it for find-what-writes to catch. */
volatile int health = 100, ammo = 30, gold = 1250;
volatile float speed = 1.5f;

__attribute__((noinline)) static void take_damage(void) {
    health = health - 1;
    if (health <= 0) health = 100;
}

int main(int argc, char** argv) {
    const int damage = argc > 1 && strcmp(argv[1], "--damage") == 0;
    printf("%p %p %p %p\n", (void*)&health, (void*)&ammo, (void*)&gold, (void*)&speed);
    fflush(stdout);
    for (;;) {
        if (damage) {
            take_damage();
            usleep(100000);
        } else {
            sleep(1);
        }
    }
}
