#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static volatile unsigned busy,worker_run=1;
static volatile unsigned user_ready;
static volatile unsigned detach_calls;
static uintptr_t frame;
static pid_t memory_peer;
static _Atomic uintptr_t last_thread;
static _Atomic int last_detach_result=INT_MIN;
static volatile unsigned peer_preserve,peer_preserved;
static void usr1_handler(int signal) {(void)signal;}
__attribute__((noinline)) static uintptr_t exec_callee(unsigned notify) {
    if(notify) syscall(SYS_tgkill,getpid(),syscall(SYS_gettid),SIGUSR1);
    int fd=open("/proc/self/mem",O_RDONLY);
    if(fd<0) _exit(20);
    char id[32],address[32],descriptor[32];
    snprintf(id,sizeof(id),"%ld",(long)memory_peer);
    // A callee exec starts a fresh application; the old mm remains available
    // through its peer and descriptor. Frame-address reuse belongs to the
    // explicit 'X' image-affinity scenario below, not this exec notification.
    snprintf(address,sizeof(address),"%x",0);
    snprintf(descriptor,sizeof(descriptor),"%d",fd);
    execl("/proc/self/exe","call-image-fixture",id,address,descriptor,"replacement",NULL);
    _exit(21);
}
static void* worker(void* ignored) {
    (void)ignored;
    while(worker_run) usleep(1000);
    return NULL;
}
static void* exec_thread(void* ignored) {
    (void)ignored;
    busy=1;
    printf("CALL_EXEC_THREAD %ld %lx %lx\n",(long)syscall(SYS_gettid),(unsigned long)(uintptr_t)&busy,
           (unsigned long)(uintptr_t)&user_ready);fflush(stdout);
    user_ready=1;
    while(busy)__asm__ volatile("":::"memory");
    return NULL;
}
__attribute__((noinline)) static int create(pthread_t* thread,const pthread_attr_t* attributes,
    void*(*entry)(void*),void* argument) {
    frame=entry==worker ? 0 : (uintptr_t)entry-64;
    int result=pthread_create(thread,attributes,entry,argument);
    if(!result)atomic_store_explicit(&last_thread,(uintptr_t)*thread,memory_order_release);
    return result;
}
__attribute__((noinline)) static int detach_thread(pthread_t thread) {
    ++detach_calls;
    return pthread_detach(thread);
}
__attribute__((noinline)) static int exec_detach(pthread_t thread) {
    (void)thread;
    ++detach_calls;
    return (int)exec_callee(0);
}
__attribute__((noinline)) static int signal_exec_detach(pthread_t thread) {
    (void)thread;
    ++detach_calls;
    return (int)exec_callee(1);
}
__attribute__((noinline)) static int signal_detach_thread(pthread_t thread) {
    ++detach_calls;
    syscall(SYS_tgkill,getpid(),syscall(SYS_gettid),SIGUSR1);
    int result=pthread_detach(thread);
    atomic_store_explicit(&last_detach_result,result,memory_order_release);
    return result;
}
static int peer_wait(void* opaque) {
    const pid_t parent=*(pid_t*)opaque;
    syscall(SYS_prctl,PR_SET_PDEATHSIG,SIGKILL,0,0,0);
    if(syscall(SYS_getppid)!=parent) syscall(SYS_exit,0);
    syscall(SYS_close,0);syscall(SYS_close,1);
    for(;;) {
        if(peer_preserve && !peer_preserved) {
            syscall(SYS_prctl,PR_SET_PDEATHSIG,0,0,0,0);
            peer_preserved=1;
        }
        if(peer_preserved && syscall(SYS_getppid)!=parent) syscall(SYS_exit,0);
        struct timespec tick={0,100000000};
        syscall(SYS_ppoll,NULL,0,&tick,NULL,8);
    }
    return 0;
}
int main(int argc,char** argv) {
    const int replacement=argc==5 || argc==6;
    const size_t page=(size_t)sysconf(_SC_PAGESIZE),size=(4+(1024*1024+page-1)/page)*page;
    pid_t peer;
    if(replacement) {
        peer=atoi(argv[1]);frame=strtoull(argv[2],NULL,16);int fd=atoi(argv[3]);
        if(frame) {
            void* memory=mmap((void*)frame,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
            if(memory==MAP_FAILED && errno==EEXIST) {
                // On i386 the replacement loader can occupy the old frame's
                // address. Re-exec our own fixture, retaining the original mm
                // descriptor, until ASLR leaves that address free.
                const unsigned attempts=argc==6 ? (unsigned)atoi(argv[5]) : 0;
                if(attempts<32) {
                    char attempt[16];snprintf(attempt,sizeof(attempt),"%u",attempts+1);
                    execl("/proc/self/exe","call-image-fixture",argv[1],argv[2],argv[3],"replacement",attempt,NULL);
                }
            }
            if(memory==MAP_FAILED){perror("replacement frame mmap");return 10;}
            for(size_t offset=0;offset<size;) {
                ssize_t got=pread(fd,(char*)memory+offset,size-offset,frame+offset);
                if(got<=0){perror("replacement frame pread");return 11;}
                offset+=(size_t)got;
            }
            if(mprotect(memory,page,PROT_READ|PROT_EXEC) ||
                mprotect((char*)memory+page,page,PROT_NONE) ||
                mprotect((char*)memory+size-2*page,page,PROT_NONE)) return 12;
        }
        close(fd);
    } else {
        void* stack=mmap(NULL,page*16,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(stack==MAP_FAILED)return 2;
        static pid_t parent;parent=getpid();
        peer=clone(peer_wait,(char*)stack+page*16,CLONE_VM|SIGCHLD,&parent);
        if(peer<0)return 3;
    }
    memory_peer=peer;
    struct sigaction action={0};action.sa_handler=usr1_handler;
    sigaction(SIGUSR1,&action,NULL);
    prctl(PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0);
    printf("CALL_IMAGE_READY %ld %ld %zu %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx\n",(long)getpid(),(long)peer,size,
        (unsigned long)(uintptr_t)create,(unsigned long)(uintptr_t)detach_thread,
        (unsigned long)(uintptr_t)worker,(unsigned long)(uintptr_t)&busy,(unsigned long)frame,
        (unsigned long)(uintptr_t)&frame,(unsigned long)(uintptr_t)&detach_calls,(unsigned long)(uintptr_t)exec_callee,
        (unsigned long)(uintptr_t)exec_detach,(unsigned long)(uintptr_t)signal_exec_detach,
        (unsigned long)(uintptr_t)signal_detach_thread,(unsigned long)(uintptr_t)&last_detach_result,
        (unsigned long)(uintptr_t)&user_ready);fflush(stdout);
    char command;
    while(read(0,&command,1)==1) {
        if(command=='Q')break;
        if(command=='D') {
            int result=pthread_detach((pthread_t)atomic_load_explicit(&last_thread,memory_order_acquire));
            printf("CALL_LEASE_DETACHED %d\n",result);fflush(stdout);
        }
        if(command=='T') {
            user_ready=0;
            peer_preserve=1;
            while(!peer_preserved)usleep(1000);
            pthread_t thread;
            if(pthread_create(&thread,NULL,exec_thread,NULL))return 22;
            pthread_detach(thread);
        }
        if(command=='R') {
            worker_run=0;puts("CALL_IMAGE_RELEASED");fflush(stdout);
        }
        if(command=='B') {
            user_ready=0;
            busy=1;puts("CALL_IMAGE_BUSY");fflush(stdout);
            user_ready=1;
            while(busy)__asm__ volatile("":::"memory");
            puts("CALL_IMAGE_RESUMED");fflush(stdout);
        }
        if(command=='X') {
            int fd=open("/proc/self/mem",O_RDONLY);if(fd<0)return 4;
            char id[32],address[32],descriptor[32];
            snprintf(id,sizeof(id),"%ld",(long)peer);snprintf(address,sizeof(address),"%lx",(unsigned long)frame);snprintf(descriptor,sizeof(descriptor),"%d",fd);
            execl("/proc/self/exe","call-image-fixture",id,address,descriptor,"replacement",NULL);return 5;
        }
    }
    kill(peer,SIGKILL);while(waitpid(peer,NULL,0)<0&&errno==EINTR){}
    return 0;
}
