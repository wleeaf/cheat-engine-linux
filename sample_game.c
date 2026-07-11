// A tiny interactive "game" to practice with Cheat Engine.
//
// Stats live in a heap-allocated Player struct reached through a global
// pointer (g_player) so you can also practice pointer scanning. Some values
// drift over time (health/mana regen, XP) so you can practice Next Scan
// (increased / decreased / changed value).
//
// Single-key commands (no Enter needed):
//   d  take 25 damage        h  heal 25
//   g  +100 gold             s  -50 gold
//   a  +10 ammo              f  fire (-1 ammo)
//   x  +50 XP                r  reset stats
//   q  quit
//
// Build:  gcc -O0 -pthread -o sample_game sample_game.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <termios.h>
#include <sys/select.h>
#include <sys/prctl.h>

typedef struct {
    int32_t health;      // 4 bytes
    int32_t maxHealth;   // 4 bytes
    int32_t gold;        // 4 bytes
    int32_t ammo;        // 4 bytes
    float   mana;        // Float
    int32_t xp;          // 4 bytes
    int32_t level;       // 4 bytes
    char    name[24];    // Text (String)
} Player;

static Player* g_player = NULL;   // global pointer -> heap Player
static volatile int g_running = 1;

static struct termios g_saved_termios;
static void restore_term(void) { tcsetattr(0, TCSANOW, &g_saved_termios); }

static void reset_stats(Player* p) {
    p->health = 100;  p->maxHealth = 100;
    p->gold = 500;    p->ammo = 30;
    p->mana = 50.0f;  p->xp = 0;   p->level = 1;
    strcpy(p->name, "Hero");
}

int main(void) {
#ifdef PR_SET_PTRACER
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);  // let CE attach w/o root
#endif
    g_player = (Player*)calloc(1, sizeof(Player));
    reset_stats(g_player);

    printf("=== Sample Game (Cheat Engine practice) ===\n");
    printf("PID=%d   Player struct @ %p   &g_player=%p\n",
           getpid(), (void*)g_player, (void*)&g_player);
    printf("Scan for these values; commands change them so you can Next Scan.\n");
    printf("Keys: d=damage h=heal g=+gold s=-gold a=+ammo f=fire x=+xp r=reset q=quit\n\n");

    // Raw, non-blocking single-key input.
    tcgetattr(0, &g_saved_termios);
    atexit(restore_term);
    struct termios t = g_saved_termios;
    t.c_lflag &= ~(ICANON | ECHO);
    t.c_cc[VMIN] = 0; t.c_cc[VTIME] = 0;
    tcsetattr(0, TCSANOW, &t);

    int tick = 0;
    while (g_running) {
        Player* p = g_player;

        // Passive drift (every ~half second) so values move on their own.
        if (p->mana < 100.0f) p->mana += 0.7f;
        if (p->health < p->maxHealth) p->health += 1;
        p->xp += 2;
        while (p->xp >= p->level * 100) {          // level up
            p->xp -= p->level * 100;
            p->level += 1;
            p->maxHealth += 10;
            p->health = p->maxHealth;
        }

        printf("\r[%-10s L%-2d] HP %4d/%-4d  Gold %-6d  Ammo %-3d  Mana %6.1f  XP %-4d   > ",
               p->name, p->level, p->health, p->maxHealth, p->gold, p->ammo, p->mana, p->xp);
        fflush(stdout);

        // Wait up to 500 ms for a keypress.
        fd_set fds; FD_ZERO(&fds); FD_SET(0, &fds);
        struct timeval tv = { .tv_sec = 0, .tv_usec = 500000 };
        if (select(1, &fds, NULL, NULL, &tv) > 0) {
            char c = 0;
            if (read(0, &c, 1) == 1) {
                switch (c) {
                    case 'd': p->health -= 25; if (p->health < 0) p->health = 0; break;
                    case 'h': p->health += 25; if (p->health > p->maxHealth) p->health = p->maxHealth; break;
                    case 'g': p->gold += 100; break;
                    case 's': p->gold -= 50; if (p->gold < 0) p->gold = 0; break;
                    case 'a': p->ammo += 10; break;
                    case 'f': if (p->ammo > 0) p->ammo -= 1; break;
                    case 'x': p->xp += 50; break;
                    case 'r': reset_stats(p); break;
                    case 'q': g_running = 0; break;
                    default: break;
                }
            }
        }
        tick++;
    }

    printf("\nBye!\n");
    free(g_player);
    return 0;
}
