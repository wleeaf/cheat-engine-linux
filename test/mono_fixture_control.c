#include <stdint.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>

static volatile unsigned waiting;
void mono_fixture_wait(void* objectData,int collections,int value,void* compute,void* other,void* longMethod) {
    prctl(PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0);
    waiting=1;
    printf("MONO_READY %d %zu %p %p %d %d %p %p %p\n",(int)getpid(),sizeof(void*),
           (void*)&waiting,objectData,collections,value,compute,other,longMethod);
    fflush(stdout);
    while (waiting) __asm__ volatile("" ::: "memory");
}
