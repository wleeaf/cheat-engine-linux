/* The game the tutorial teaches you to change.

   Each step allocates its objects on the heap when it starts and keeps them in
   one of this file's static pointers, the way a real game keeps its state.
   Nothing is freed while the tutorial runs, so an address you froze in an
   earlier step never lands in reused memory.

   The functions marked GAME_CODE are the code you find and change in steps 5,
   7 and 9. They stay out of line and this file is built at -O1 without
   sanitizers (see CMakeLists.txt), so each of those changes is one plain
   instruction. Checks read values through LOAD so the compiler cannot assume
   it knows what a changed instruction stored. */

#include "game.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__clang__)
#define GAME_CODE __attribute__((noinline, used))
#else
#define GAME_CODE __attribute__((noipa, used))
#endif
#define LOAD(x) (*(volatile __typeof__(x)*)&(x))

/* ── Step objects ── */

struct Step2 { char name[16]; int32_t level; int32_t health; };        /* health at +0x14 */
struct Step4 { int32_t level; float health; double ammo; };             /* +0x4 and +0x8 */
struct Step5 { int64_t id; int32_t value; };                            /* +0x8 */
struct Step6 { int64_t id; int64_t flags; int32_t value; };             /* +0x10 */
struct Step7 { char inventory[0x7f8]; int32_t health; };                /* +0x7f8 */
struct Step8Value { char pad[0x18]; int32_t value; };
struct Step8C { struct Step8Value* next; };                             /* +0x0 */
struct Step8B { char pad[0x18]; struct Step8C* next; };                 /* +0x18 */
struct Step8A { char pad[0x10]; struct Step8B* next; };                 /* +0x10 */
struct Player { int32_t id; float health; char name[16]; int32_t team; };

static struct Step2* step2;
static struct Step2* step3;
static struct Step4* step4;
static struct Step5* step5;
static struct Step6* step6;
static struct Step7* step7;
static struct Step8A* step8;
static struct Player* players[4];

static int current_step = 1;
static int step_done = 1;
static int finished = 0;
static long long clock_ms = 0;
static long long check_until = 0;   /* steps 6 and 8: end of the 3 second window */
static int check_pending = 0;       /* a pointer changed; the window starts at the next tick */

/* Step 9's battle. Who is out lives here, not in the players, so the only
   field that tells the teams apart is the team. */
static int battle_running = 0;
static int battle_rounds = 0;
static unsigned char player_out[4];
static long long next_round_ms = 0;

static uint32_t rng_state = 1;

static uint32_t rnd(void) {
    uint32_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return rng_state = x;
}

static int rnd_range(int lo, int hi) { return lo + (int)(rnd() % (uint32_t)(hi - lo + 1)); }

static void* object(size_t size) {
    void* p = calloc(1, size);
    if (!p) abort();
    return p;
}

/* An object for a pointer step, with unused room of random size after it, so
   objects allocated together are not neighbours at fixed distances. Otherwise
   a pointer scan finds shortcuts ([object]+offset into its neighbour) that
   survive a rescan by luck of the allocator. */
static void* scattered(size_t size) {
    return object(size + (size_t)rnd_range(1, 256) * 16);
}

/* ── The code you change ── */

GAME_CODE void tutorial_set_value(struct Step5* s, int32_t value) {
    s->value = value;                  /* step 5: replace this with nothing */
}

GAME_CODE void tutorial_hit(struct Step7* s) {
    s->health -= 1;                    /* step 7: make this add 2 */
}

GAME_CODE int tutorial_take_damage(struct Player* p, float amount) {
    p->health -= amount;               /* step 9: every player's health is written here */
    return LOAD(p->health) <= 0.0f;    /* read back, so skipping the write spares the player */
}

/* ── Steps ── */

static const char* const titles[TUT_STEPS] = {
    "Welcome",
    "Exact value",
    "Unknown initial value",
    "Floating point values",
    "Code finder",
    "Pointers",
    "Code injection",
    "Multilevel pointers",
    "Shared code",
};

static const char* const texts[TUT_STEPS] = {
    /* 1 */
    "This tutorial teaches the basics of changing a game with Cheat Engine: "
    "finding values, following pointers and changing the code that writes them. "
    "Keep it open next to Cheat Engine.\n\n"
    "Start Cheat Engine, press Ctrl+O (or the computer button at the top left), "
    "choose cetutorial in the list and click Open. Then press Next.\n\n"
    "Every step shows a password. Enter it here later to go straight back to that step.",

    /* 2 */
    "Your health is 100, and Hit me takes some of it away. Change it to 1000.\n\n"
    "In Cheat Engine, set Value Type to 4 Bytes, type 100 in the value box and press "
    "First Scan. Many addresses hold 100, so press Hit me, type your new health and "
    "press Next Scan. Repeat until one or two addresses are left.\n\n"
    "Double-click the address to add it to the address list at the bottom, then "
    "double-click its value and type 1000. The step completes as soon as health is 1000.",

    /* 3 */
    "This time you cannot see your health. It starts somewhere between 100 and 900, "
    "and Hit me only tells you how much you lost. Change it to 5000.\n\n"
    "Set Scan Type to Unknown initial value and press First Scan. Press Hit me, choose "
    "Decreased value (or Decreased value by... with the amount you lost) and press Next "
    "Scan. While nothing happens in the game, a scan for Unchanged value clears away "
    "addresses that change on their own. Repeat until few addresses are left, then "
    "set health to 5000.",

    /* 4 */
    "Games often keep values as floating point numbers. Here health is a Float and "
    "ammo a Double. Change both to 5000.\n\n"
    "Scan with Value Type Float for health and Double for ammo. The window shows one "
    "decimal; scan for the number you see and Cheat Engine matches the rounded value.",

    /* 5 */
    "Change value writes a new number every time. Instead of changing the value, "
    "change the code that writes it.\n\n"
    "Find the value and add it to the address list. Right-click it and choose Find out "
    "what writes to this address, then press Change value: the instruction that wrote "
    "it appears. Right-click the instruction and choose Replace with code that does "
    "nothing (NOP). Press Change value again; when the value stays the same, the step "
    "is complete.",

    /* 6 */
    "The value is reached through a pointer, and Change pointer moves it to a new "
    "address, as a game does when it loads a level. Find the pointer, so your change "
    "survives the move: within three seconds after Change pointer, the value must be 5000.\n\n"
    "Find the value, right-click it and choose Pointer scan for this address. Press "
    "Change pointer, find the value again, and use Rescan... with its new address: the "
    "paths left still lead to it. Add one to the address list, set it to 5000, tick "
    "its Active box to freeze it and press Change pointer.\n\n"
    "You can also follow the pointer by hand: Find out what accesses this address shows "
    "an instruction such as mov eax,[rdx+10]. Scan for the value of rdx (8 Bytes, Hex) "
    "to find where the pointer is kept, and add it with Add Address Manually, Pointer.",

    /* 7 */
    "Hit me takes 1 health away. Make it add 2 instead, with a code injection.\n\n"
    "Find your health, choose Find out what writes to this address and press Hit me. "
    "Right-click the instruction (a sub on [rdi+7F8]) and choose Show in the "
    "disassembler. There, right-click it and choose Auto Assemble, Create code "
    "injection here. In the script, replace the sub instruction under code: with "
    "add dword ptr [rdi+7F8],2 and execute it, or add it to the table and tick it. "
    "When Hit me adds 2, the step is complete.",

    /* 8 */
    "Like step 6, but the value is four pointers deep, and Change pointer replaces "
    "every object on the way. Within three seconds after Change pointer, the value "
    "must be 5000.\n\n"
    "A pointer scan with a maximum level of 4 finds the path; use Rescan... after Change "
    "pointer to keep only the paths that still work. You can also follow it by hand, one "
    "level at a time: find what accesses the value, scan for the pointer it came from, "
    "and repeat for that address until you reach a green (static) address.",

    /* 9 */
    "Ada and Grace (team 1) fight Raider and Brute (team 2). The raiders kill with one "
    "hit, and a single function deals all the damage, to friend and foe alike. Make "
    "team 1 win: both raiders out while Ada and Grace are still in.\n\n"
    "Freezing will not help, because one hit is enough. Find Ada's health (Float) "
    "and find out what writes to it during a battle: one instruction writes everyone's "
    "health. In the disassembler, Find out what addresses this instruction accesses "
    "shows all four players. Compare them in Dissect data/structures: one field is 1 "
    "for Ada and Grace and 2 for the raiders. Inject code that skips the write for "
    "team 1, then press Restart battle.",
};

static const char* const passwords[TUT_STEPS] = {
    "", "LX4F2Q", "RM8K3T", "BW6N1D", "HJ2P9C", "TQ5V7Z", "KD3R8M", "YF9W4H", "PN7C2X",
};

static const char* const player_names[4] = {"Ada", "Grace", "Raider", "Brute"};

static void enter_step(int step) {
    current_step = step;
    step_done = step == 1;
    check_pending = 0;
    check_until = 0;
    battle_running = 0;
    switch (step) {
    case 2:
        if (!step2) step2 = object(sizeof *step2);
        strcpy(step2->name, "Player");
        step2->level = 1;
        step2->health = 100;
        break;
    case 3:
        if (!step3) step3 = object(sizeof *step3);
        strcpy(step3->name, "Player");
        step3->level = 2;
        step3->health = rnd_range(100, 900);
        break;
    case 4:
        if (!step4) step4 = object(sizeof *step4);
        step4->level = 3;
        step4->health = 100.0f;
        step4->ammo = 100.0;
        break;
    case 5:
        if (!step5) step5 = object(sizeof *step5);
        step5->id = 5;
        step5->value = 100;
        break;
    case 6:
        step6 = scattered(sizeof *step6);
        step6->id = 6;
        step6->value = 100;
        break;
    case 7:
        if (!step7) step7 = object(sizeof *step7);
        step7->health = 100;
        break;
    case 8: {
        struct Step8A* a = scattered(sizeof *a);
        a->next = scattered(sizeof *a->next);
        a->next->next = scattered(sizeof *a->next->next);
        a->next->next->next = scattered(sizeof *a->next->next->next);
        a->next->next->next->value = 100;
        step8 = a;
        break;
    }
    case 9:
        for (int i = 0; i < 4; ++i) {
            if (!players[i]) players[i] = object(sizeof *players[i]);
            players[i]->id = i + 1;
            players[i]->team = i < 2 ? 1 : 2;
            players[i]->health = i < 2 ? 100.0f : 200.0f;
            snprintf(players[i]->name, sizeof players[i]->name, "%s", player_names[i]);
            player_out[i] = 0;
        }
        battle_rounds = 0;
        break;
    }
}

void tut_init(unsigned seed) {
    rng_state = seed ? seed : (uint32_t)time(NULL) ^ 0x9e3779b9u;
    if (!rng_state) rng_state = 1;
    finished = 0;
    enter_step(1);
}

int tut_step(void) { return current_step; }
int tut_finished(void) { return finished; }
int tut_done(void) { return step_done; }

int tut_next(void) {
    if (!step_done || finished) return 0;
    if (current_step == TUT_STEPS) finished = 1;
    else enter_step(current_step + 1);
    return 1;
}

const char* tut_title(int step) { return step >= 1 && step <= TUT_STEPS ? titles[step - 1] : ""; }
const char* tut_text(int step) { return step >= 1 && step <= TUT_STEPS ? texts[step - 1] : ""; }
const char* tut_password(int step) { return step >= 1 && step <= TUT_STEPS ? passwords[step - 1] : ""; }

const char* tut_finished_text(void) {
    return "You finished the tutorial. You can now find values of every common type, "
           "follow pointers, and change the code that writes them.\n\n"
           "Try the graphical tutorial (cegtutorial) next, or open a real single-player "
           "game. Save what you find as a table (File, Save) so it works next time.";
}

int tut_unlock(const char* password) {
    if (!password || current_step != 1) return 0;
    for (int step = 2; step <= TUT_STEPS; ++step)
        if (strcmp(password, passwords[step - 1]) == 0) {
            enter_step(step);
            return step;
        }
    return 0;
}

/* ── Buttons ── */

struct Action { const char* label; const char* command; };

static const struct Action actions[TUT_STEPS][2] = {
    {{0, 0}, {0, 0}},
    {{"Hit me", "hit"}, {0, 0}},
    {{"Hit me", "hit"}, {0, 0}},
    {{"Hit me", "hit"}, {"Fire", "fire"}},
    {{"Change value", "change"}, {0, 0}},
    {{"Change value", "change"}, {"Change pointer", "pointer"}},
    {{"Hit me", "hit"}, {0, 0}},
    {{"Change value", "change"}, {"Change pointer", "pointer"}},
    {{"Restart battle", "battle"}, {0, 0}},
};

int tut_action_count(void) {
    if (finished) return 0;
    int n = 0;
    while (n < 2 && actions[current_step - 1][n].label) ++n;
    return n;
}

const char* tut_action_label(int index) {
    return index >= 0 && index < tut_action_count() ? actions[current_step - 1][index].label : "";
}

const char* tut_action_command(int index) {
    return index >= 0 && index < tut_action_count() ? actions[current_step - 1][index].command : "";
}

static int new_value(int32_t old) {
    int v;
    do v = rnd_range(0, 999); while (v == old);
    return v;
}

static void start_battle(char* message, size_t size) {
    for (int i = 0; i < 4; ++i) {
        players[i]->health = i < 2 ? 100.0f : 200.0f;
        player_out[i] = 0;
    }
    battle_rounds = 0;
    battle_running = 1;
    next_round_ms = 0;
    snprintf(message, size, "The battle starts.");
}

void tut_action(int index, char* message, size_t size) {
    message[0] = 0;
    if (index < 0 || index >= tut_action_count()) return;
    switch (current_step) {
    case 2: {
        const int damage = rnd_range(1, 10);
        step2->health -= damage;
        snprintf(message, size, "You lost %d health.", damage);
        break;
    }
    case 3: {
        const int damage = rnd_range(1, 10);
        step3->health -= damage;
        snprintf(message, size, "You lost %d health.", damage);
        break;
    }
    case 4:
        if (index == 0) {
            const float damage = (float)rnd_range(5, 50) / 10.0f;
            step4->health -= damage;
            snprintf(message, size, "You lost %.1f health.", damage);
        } else {
            step4->ammo -= 0.5;
            snprintf(message, size, "You fired. Ammo went down by 0.5.");
        }
        break;
    case 5: {
        const int32_t before = LOAD(step5->value);
        tutorial_set_value(step5, new_value(before));
        const int32_t after = LOAD(step5->value);
        if (after == before) {
            step_done = 1;
            snprintf(message, size, "The value did not change: the code that writes it is gone.");
        } else {
            snprintf(message, size, "The value changed to %d.", after);
        }
        break;
    }
    case 6:
        if (index == 0) {
            step6->value = new_value(step6->value);
            snprintf(message, size, "The value changed.");
        } else {
            struct Step6* moved = scattered(sizeof *moved);
            moved->id = 6;
            moved->value = new_value(LOAD(step6->value));
            step6 = moved;
            check_pending = 1;
            snprintf(message, size, "The value moved to a new address. It has 3 seconds to become 5000.");
        }
        break;
    case 7: {
        const int32_t before = LOAD(step7->health);
        tutorial_hit(step7);
        const int32_t after = LOAD(step7->health);
        if (after == before + 2) {
            step_done = 1;
            snprintf(message, size, "Hit me gave you 2 health.");
        } else if (after == before - 1) {
            snprintf(message, size, "You lost 1 health.");
        } else {
            snprintf(message, size, "Health went from %d to %d. Make Hit me add exactly 2.", before, after);
        }
        break;
    }
    case 8:
        if (index == 0) {
            step8->next->next->next->value = new_value(step8->next->next->next->value);
            snprintf(message, size, "The value changed.");
        } else {
            struct Step8A* a = scattered(sizeof *a);
            a->next = scattered(sizeof *a->next);
            a->next->next = scattered(sizeof *a->next->next);
            a->next->next->next = scattered(sizeof *a->next->next->next);
            a->next->next->next->value = new_value(LOAD(step8->next->next->next->value));
            step8 = a;
            check_pending = 1;
            snprintf(message, size, "Every pointer on the way moved. The value has 3 seconds to become 5000.");
        }
        break;
    case 9:
        start_battle(message, size);
        break;
    }
}

/* ── What the step shows ── */

int tut_field_count(void) {
    if (finished) return 0;
    switch (current_step) {
    case 1: return 0;
    case 4: return 2;
    case 9: return 4;
    default: return 1;
    }
}

const char* tut_field_label(int index) {
    if (index < 0 || index >= tut_field_count()) return "";
    switch (current_step) {
    case 4: return index == 0 ? "Health" : "Ammo";
    case 5: case 6: case 8: return "Value";
    case 9: {
        static const char* const labels[4] = {"Ada (team 1)", "Grace (team 1)", "Raider (team 2)", "Brute (team 2)"};
        return labels[index];
    }
    default: return "Health";
    }
}

void tut_field_value(int index, char* out, size_t size) {
    out[0] = 0;
    if (index < 0 || index >= tut_field_count()) return;
    switch (current_step) {
    case 2: snprintf(out, size, "%d", LOAD(step2->health)); break;
    case 3: snprintf(out, size, "???"); break;
    case 4:
        if (index == 0) snprintf(out, size, "%.1f", (double)LOAD(step4->health));
        else snprintf(out, size, "%.1f", LOAD(step4->ammo));
        break;
    case 5: snprintf(out, size, "%d", LOAD(step5->value)); break;
    case 6: snprintf(out, size, "%d", LOAD(step6->value)); break;
    case 7: snprintf(out, size, "%d", LOAD(step7->health)); break;
    case 8: snprintf(out, size, "%d", LOAD(step8->next->next->next->value)); break;
    case 9:
        if (player_out[index]) snprintf(out, size, "out");
        else snprintf(out, size, "%.1f", (double)LOAD(players[index]->health));
        break;
    }
}

/* ── Time ── */

/* The game decides teams by index, never by the team field the step asks you
   to find: changing that field must not win the battle. */
static int team_of(int i) { return i < 2 ? 1 : 2; }

static int alive(int team) {
    int n = 0;
    for (int i = 0; i < 4; ++i)
        if (team_of(i) == team && !player_out[i]) ++n;
    return n;
}

/* One attack. Turns go Ada, Raider, Grace, Brute, and each player fights a
   fixed opponent while it is in, so every battle touches all four players. */
static void battle_round(char* message, size_t size) {
    static const int order[4] = {0, 2, 1, 3};
    static const int opponent[4] = {2, 3, 0, 1};
    int attacker = -1;
    for (int tries = 0; tries < 4 && attacker < 0; ++tries) {
        const int candidate = order[battle_rounds % 4];
        ++battle_rounds;
        if (!player_out[candidate]) attacker = candidate;
    }
    if (attacker < 0) return;
    int target = opponent[attacker];
    if (player_out[target]) target = target ^ 1;   /* the other member of that team */
    if (player_out[target]) return;
    const float damage = team_of(attacker) == 1 ? (float)rnd_range(10, 25) : (float)rnd_range(120, 150);
    if (tutorial_take_damage(players[target], damage)) {
        player_out[target] = 1;
        snprintf(message, size, "%s hits %s for %.0f. %s is out.", player_names[attacker], player_names[target],
                 (double)damage, player_names[target]);
    } else {
        snprintf(message, size, "%s hits %s for %.0f.", player_names[attacker], player_names[target], (double)damage);
    }
}

int tut_tick(long long now_ms, char* message, size_t size) {
    message[0] = 0;
    clock_ms = now_ms;
    if (finished) return 0;
    switch (current_step) {
    case 2:
        if (!step_done && LOAD(step2->health) == 1000) step_done = 1;
        break;
    case 3:
        if (!step_done && LOAD(step3->health) == 5000) step_done = 1;
        break;
    case 4:
        if (!step_done && LOAD(step4->health) == 5000.0f && LOAD(step4->ammo) == 5000.0) step_done = 1;
        break;
    case 6:
    case 8: {
        if (step_done || (!check_pending && !check_until)) break;
        if (check_pending) {
            check_pending = 0;
            check_until = now_ms + 3000;
        }
        const int32_t value = current_step == 6 ? LOAD(step6->value) : LOAD(step8->next->next->next->value);
        if (value == 5000) {
            step_done = 1;
            check_until = 0;
        } else if (now_ms > check_until) {
            check_until = 0;
            snprintf(message, size, "Three seconds passed and the value at the new address is %d, not 5000. "
                                    "Freeze the pointer, not the address.", value);
            return 1;
        }
        break;
    }
    case 9: {
        if (!battle_running || now_ms < next_round_ms) break;
        next_round_ms = now_ms + 50;
        battle_round(message, size);
        const int team1 = alive(1), team2 = alive(2);
        char result[160] = "";
        if (team2 == 0 && team1 == 2) {
            step_done = 1;
            snprintf(result, sizeof result, " Team 1 wins with nobody out.");
        } else if (team2 == 0) {
            snprintf(result, sizeof result, " Team 1 wins, but lost a player. Both must stay in.");
        } else if (team1 == 0) {
            snprintf(result, sizeof result, " Team 2 wins.");
        } else if (battle_rounds >= 400) {
            snprintf(result, sizeof result, " Nobody won after %d turns. Only team 1 should be spared.", battle_rounds);
        }
        if (result[0]) {
            battle_running = 0;
            strncat(message, result, size - strlen(message) - 1);
        }
        return message[0] != 0;
    }
    }
    return 0;
}
