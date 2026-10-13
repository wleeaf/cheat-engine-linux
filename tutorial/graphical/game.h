#pragma once
/* The graphical tutorial's game: three short levels drawn in a window, each
   with a value to find and change. The window and the text mode drive it
   through these functions; like tutorial/game.h it is not thread-safe. */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { GT_LEVELS = 3 };
enum { GT_WIDTH = 640, GT_HEIGHT = 360 };   /* the world, in screen units (y grows down) */
enum { GT_LEFT = 1, GT_RIGHT = 2, GT_FIRE = 4, GT_JUMP = 8 };

typedef struct { float x, y, w, h; } GtRect;

/* Everything the window draws. */
typedef struct {
    GtRect player;
    int show_target;
    GtRect target;
    float target_health;      /* 0..1, drawn as a bar */
    int show_heat;
    float heat;               /* 0..1 */
    int jammed;
    GtRect bullets[64];
    int bullet_count;
    GtRect ground[4];
    int ground_count;
    int show_door;
    GtRect door;
    float jump_power;         /* shown in level 3 */
} GtView;

void gt_init(unsigned seed);
void gt_goto(int level);              /* start a level directly */
int gt_level(void);                  /* 1..GT_LEVELS */
int gt_finished(void);
int gt_done(void);
int gt_next(void);
const char* gt_title(int level);
const char* gt_text(int level);
const char* gt_finished_text(void);

/* Which keys are held (GT_LEFT | GT_RIGHT | GT_FIRE | GT_JUMP). */
void gt_keys(int held);
/* Advance the game by dt seconds (the front ends call it about 60 times a
   second). Returns 1 and fills message when something worth showing happened. */
int gt_tick(float dt, char* message, size_t size);
void gt_view(GtView* view);

#ifdef __cplusplus
}
#endif
