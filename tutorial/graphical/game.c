/* The graphical tutorial's game.

   Level objects live on the heap and are reached from this file's static
   pointers; the physics settings of level 3 are a static variable, as game
   constants often are. Built at -O1 without sanitizers, like tutorial/game.c. */

#include "game.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOAD(x) (*(volatile __typeof__(x)*)&(x))

struct Target { int32_t kind; int32_t health; int32_t max_health; float quiet; float repair; };
struct Gun { float heat; float jammed; int32_t shots; };
struct Body { float x, y, vx, vy; int32_t on_ground; };
struct Physics { float gravity; float jump_power; float run_speed; };
struct Bullet { float x, y; };

/* The level's target: level 1 and 2 each have their own, so a value frozen in
   level 1 cannot finish level 2. */
static struct Target* target;
static struct Target* target1;
static struct Target* target2;
static struct Gun* gun;
static struct Body* body;
/* Set when level 3 starts and read through LOAD, so it stays in writable
   memory and a changed value takes effect. */
static struct Physics physics;

static struct Bullet bullets[64];
static int bullet_count;
static float fire_wait;
static int keys;
static int level = 1;
static int level_done;
static int finished;
static uint32_t rng_state = 1;

static const GtRect floor_rect = {0, 320, GT_WIDTH, 40};
static const GtRect ledge = {420, 180, 220, 180};
static const GtRect door = {585, 136, 26, 44};
static const GtRect target_rect = {295, 40, 50, 50};

static uint32_t rnd(void) {
    uint32_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return rng_state = x;
}

static void* object(size_t size) {
    void* p = calloc(1, size);
    if (!p) abort();
    return p;
}

static int overlap(GtRect a, GtRect b) {
    return a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
}

static const char* const titles[GT_LEVELS] = {"Target practice", "Overheating", "Jump power"};

static const char* const texts[GT_LEVELS] = {
    "Shoot the target with Space. Its health is only shown as a bar, and it recovers "
    "when you stop shooting. Destroy it.\n\n"
    "In Cheat Engine, open cegtutorial and scan for an Unknown initial value (4 Bytes). "
    "Shoot a few times and scan for Decreased value; wait until the bar refills and "
    "scan for Increased value. After a few rounds, set what is left to 0.",

    "The fortress repairs itself faster than you can hurt it: your gun overheats after "
    "six quick shots and then jams for three seconds. The heat bar is a Float.\n\n"
    "Scan for an Unknown initial value with Value Type Float. Shoot (Increased value), "
    "wait (Decreased value) and repeat. Freeze the heat at 0, then hold Space until "
    "the fortress falls.",

    "The door is on a ledge you cannot reach: your jump power is 420. Raise it.\n\n"
    "Scan for the Float 420. Settings the game never changes usually sit in its "
    "static memory, so the address shows as cegtutorial+offset. Change it to 900, then "
    "run right with the arrow keys and jump (Up) onto the ledge and into the door.",
};

static void enter_level(int n) {
    level = n;
    level_done = 0;
    bullet_count = 0;
    fire_wait = 0;
    switch (n) {
    case 1:
        if (!target1) target1 = object(sizeof *target1);
        target = target1;
        *target = (struct Target){1, 500, 500, 0, 0};
        break;
    case 2:
        if (!gun) gun = object(sizeof *gun);
        if (!target2) target2 = object(sizeof *target2);
        target = target2;
        *gun = (struct Gun){0, 0, 0};
        *target = (struct Target){2, 120, 120, 0, 0};
        break;
    case 3:
        if (!body) body = object(sizeof *body);
        physics = (struct Physics){1400.0f, 420.0f, 180.0f};
        *body = (struct Body){40, floor_rect.y - 28, 0, 0, 1};
        break;
    }
}

void gt_init(unsigned seed) {
    rng_state = seed ? seed : (uint32_t)time(NULL) ^ 0x85ebca6bu;
    if (!rng_state) rng_state = 1;
    finished = 0;
    keys = 0;
    enter_level(1);
}

void gt_goto(int n) {
    if (n >= 1 && n <= GT_LEVELS) enter_level(n);
}

int gt_level(void) { return level; }
int gt_finished(void) { return finished; }
int gt_done(void) { return level_done; }
const char* gt_title(int n) { return n >= 1 && n <= GT_LEVELS ? titles[n - 1] : ""; }
const char* gt_text(int n) { return n >= 1 && n <= GT_LEVELS ? texts[n - 1] : ""; }

const char* gt_finished_text(void) {
    return "You finished the graphical tutorial: a value seen only as a bar, a value "
           "you had to freeze, and a setting the game never changes.";
}

int gt_next(void) {
    if (!level_done || finished) return 0;
    if (level == GT_LEVELS) finished = 1;
    else enter_level(level + 1);
    return 1;
}

void gt_keys(int held) { keys = held; }

static GtRect player_rect(void) {
    if (level == 3) return (GtRect){body->x, body->y, 20, 28};
    return (GtRect){310, 300, 20, 20};
}

/* Bullets fly up from the ship; a hit on the target costs it health. */
static void shoot_and_hit(float dt, int damage_lo, int damage_hi) {
    for (int i = 0; i < bullet_count;) {
        bullets[i].y -= 600.0f * dt;
        const GtRect r = {bullets[i].x - 2, bullets[i].y, 4, 10};
        if (overlap(r, target_rect) && target->health > 0) {
            target->health -= damage_lo + (int)(rnd() % (uint32_t)(damage_hi - damage_lo + 1));
            target->quiet = 0;
            bullets[i] = bullets[--bullet_count];
        } else if (bullets[i].y < -10) {
            bullets[i] = bullets[--bullet_count];
        } else {
            ++i;
        }
    }
}

static int fire(float interval) {
    if (!(keys & GT_FIRE) || fire_wait > 0 || bullet_count >= 64) return 0;
    fire_wait = interval;
    bullets[bullet_count++] = (struct Bullet){320, 296};
    return 1;
}

static void move_body(float dt) {
    struct Body* b = body;
    b->vx = (float)(((keys & GT_RIGHT) ? 1 : 0) - ((keys & GT_LEFT) ? 1 : 0)) * LOAD(physics.run_speed);
    if ((keys & GT_JUMP) && b->on_ground) {
        b->vy = -LOAD(physics.jump_power);
        b->on_ground = 0;
    }
    /* Across: the ledge is a wall for anyone below its top. */
    float x = b->x + b->vx * dt;
    if (b->y + 28 > ledge.y + 0.5f && x + 20 > ledge.x && b->x + 20 <= ledge.x + 0.5f) x = ledge.x - 20;
    if (x < 0) x = 0;
    if (x > GT_WIDTH - 20) x = GT_WIDTH - 20;
    b->x = x;
    /* Down: land on the floor or the ledge. */
    b->vy += LOAD(physics.gravity) * dt;
    const float bottom = b->y + 28;
    float y = b->y + b->vy * dt;
    b->on_ground = 0;
    const GtRect grounds[2] = {floor_rect, ledge};
    for (int i = 0; i < 2; ++i) {
        const GtRect g = grounds[i];
        if (b->vy >= 0 && bottom <= g.y + 0.5f && y + 28 >= g.y && b->x + 20 > g.x && b->x < g.x + g.w) {
            y = g.y - 28;
            b->vy = 0;
            b->on_ground = 1;
        }
    }
    b->y = y;
}

int gt_tick(float dt, char* message, size_t size) {
    message[0] = 0;
    if (finished || level_done) return 0;
    if (fire_wait > 0) fire_wait -= dt;
    switch (level) {
    case 1:
        fire(0.15f);
        shoot_and_hit(dt, 2, 4);
        if (LOAD(target->health) <= 0) {
            level_done = 1;
            snprintf(message, size, "The target is destroyed.");
            return 1;
        }
        /* After 1.5 quiet seconds the target repairs 40 health a second. */
        target->quiet += dt;
        if (target->quiet > 1.5f && target->health < target->max_health) {
            target->repair += 40.0f * dt;
            while (target->repair >= 1.0f && target->health < target->max_health) { target->health += 1; target->repair -= 1.0f; }
        }
        break;
    case 2: {
        int jam_message = 0;
        if (gun->jammed > 0) {
            gun->jammed -= dt;
        } else if (fire(0.12f)) {
            gun->heat += 20.0f;
            gun->shots += 1;
            if (LOAD(gun->heat) >= 100.0f) {
                gun->jammed = 3.0f;
                jam_message = 1;
            }
        }
        if (gun->heat > 0) gun->heat -= 15.0f * dt;
        if (gun->heat < 0) gun->heat = 0;
        shoot_and_hit(dt, 6, 6);
        if (LOAD(target->health) <= 0) {
            level_done = 1;
            snprintf(message, size, "The fortress falls.");
            return 1;
        }
        /* The fortress repairs 25 health a second, all the time. */
        target->repair += 25.0f * dt;
        while (target->repair >= 1.0f) { if (target->health < target->max_health) target->health += 1; target->repair -= 1.0f; }
        if (jam_message) {
            snprintf(message, size, "The gun overheated and jammed for three seconds.");
            return 1;
        }
        break;
    }
    case 3:
        move_body(dt);
        if (overlap(player_rect(), door)) {
            level_done = 1;
            snprintf(message, size, "You reached the door.");
            return 1;
        }
        break;
    }
    return 0;
}

void gt_view(GtView* v) {
    memset(v, 0, sizeof *v);
    v->player = player_rect();
    if (level <= 2 && !finished) {
        v->show_target = 1;
        v->target = target_rect;
        const float health = (float)LOAD(target->health) / (float)target->max_health;
        v->target_health = !(health > 0) ? 0 : health > 1 ? 1 : health;   /* NaN after a changed max_health */
        for (int i = 0; i < bullet_count; ++i) v->bullets[v->bullet_count++] = (GtRect){bullets[i].x - 2, bullets[i].y, 4, 10};
        v->ground[v->ground_count++] = floor_rect;
    }
    if (level == 2 && !finished) {
        v->show_heat = 1;
        const float heat = LOAD(gun->heat) / 100.0f;
        v->heat = !(heat > 0) ? 0 : heat > 1 ? 1 : heat;   /* the heat may be set to NaN */
        v->jammed = gun->jammed > 0;
    }
    if (level == 3 && !finished) {
        v->ground[v->ground_count++] = floor_rect;
        v->ground[v->ground_count++] = ledge;
        v->show_door = 1;
        v->door = door;
        v->jump_power = LOAD(physics.jump_power);
    }
}
