#pragma once
/* The tutorial's game: nine steps, each a value or a piece of code to find and
   change with Cheat Engine. The Qt window and the text mode both drive it
   through these functions, so the memory and code you change are the same in
   either. Not thread-safe: a front end that ticks from another thread holds
   its own lock around every call. */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { TUT_STEPS = 9 };

/* Start at step 1. A seed of 0 picks one from the clock. */
void tut_init(unsigned seed);

int tut_step(void);                   /* 1..TUT_STEPS */
int tut_finished(void);               /* Next was pressed on the last step */
int tut_done(void);                   /* the current step is complete */
int tut_next(void);                   /* go to the next step; 0 if not done */
const char* tut_title(int step);
const char* tut_text(int step);       /* paragraphs separated by blank lines */
const char* tut_finished_text(void);
const char* tut_password(int step);   /* opens that step from step 1 */
int tut_unlock(const char* password); /* the step it opened, or 0 */

/* The buttons of the current step: a label for the window and a one-word
   command for the text mode. tut_action runs one and describes what happened. */
int tut_action_count(void);
const char* tut_action_label(int index);
const char* tut_action_command(int index);
void tut_action(int index, char* message, size_t size);

/* What the step shows on screen. Hidden values read "???". */
int tut_field_count(void);
const char* tut_field_label(int index);
void tut_field_value(int index, char* out, size_t size);

/* Call about every 50 ms. Runs timed checks (steps 6 and 8) and the battle of
   step 9. Returns 1 and fills message when something worth showing happened. */
int tut_tick(long long now_ms, char* message, size_t size);

#ifdef __cplusplus
}
#endif
