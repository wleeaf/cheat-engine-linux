/* A freestanding target: i386 tests need no 32-bit libc or runtime loader. */
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <asm/unistd.h>
typedef __UINTPTR_TYPE__ uptr;
typedef __INTPTR_TYPE__ iptr;
enum { NR_READ=__NR_read,NR_WRITE=__NR_write,NR_EXIT=__NR_exit,NR_GETPID=__NR_getpid,
       NR_PRCTL=__NR_prctl,NR_EXECVE=__NR_execve,NR_GETTID=__NR_gettid,
       NR_TGKILL=__NR_tgkill,NR_SIGMASK=__NR_rt_sigprocmask,
#if defined(__i386__)
       NR_MAP=__NR_mmap2
#else
       NR_MAP=__NR_mmap
#endif
};
#define FIXTURE_STRING_VALUE(value) #value
#define FIXTURE_STRING(value) FIXTURE_STRING_VALUE(value)

static volatile unsigned value = 123456789;
static uptr pointer = (uptr)&value;
static volatile unsigned spinning;
static volatile unsigned siblingMode, siblingReady, siblingDone, heartbeat;
static volatile unsigned char dispatchSelector;
static volatile unsigned callWaiting=1, callEntered;
static volatile unsigned callDetached;
static char threadStack[16384] __attribute__((aligned(16), used));
static char ownerThreadStack[16384] __attribute__((aligned(16), used));
static unsigned ownerConsoleStage,ownerConsoleReady;
static const char* fixtureNext;
extern void fixtureCaller(void), fixtureCallSite(void), fixtureAfterCall(void), fixtureReturnSite(void);
extern iptr fixtureSpawnThread(void);
extern iptr fixtureSpawnOnStack(void*);
extern void fixtureExitSite(void);
__attribute__((noreturn)) extern void fixtureExitThread(void);
extern void fixtureUserTrap(void), fixtureUserTrapSite(void), fixtureExecSite(void), fixtureSyscallSite(void);
extern iptr fixtureExecThread(const char*,const char* const*,const char* const*), fixtureProbeSyscall(void);
__attribute__((noreturn, used)) void fixtureThread(void);

#if defined(__x86_64__)
static iptr systemCallArgs(iptr nr, uptr a, uptr b, uptr c, uptr d, uptr e, uptr f) {
    register uptr arg4 __asm__("r10") = d;
    register uptr arg5 __asm__("r8") = e;
    register uptr arg6 __asm__("r9") = f;
    iptr result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(nr), "D"(a), "S"(b), "d"(c),
                     "r"(arg4), "r"(arg5), "r"(arg6) : "rcx", "r11", "memory");
    return result;
}
#elif defined(__i386__)
static iptr systemCallArgs(iptr nr, uptr a, uptr b, uptr c, uptr d, uptr e, uptr f) {
    iptr result;
    /* The fixture needs five prctl arguments; no call here uses the sixth. */
    (void)f;
    __asm__ volatile("int $0x80" : "=a"(result) : "a"(nr), "b"(a), "c"(b), "d"(c), "S"(d), "D"(e) : "memory");
    return result;
}
#elif defined(__aarch64__)
static iptr systemCallArgs(iptr nr, uptr a, uptr b, uptr c, uptr d, uptr e, uptr f) {
    register uptr x0 __asm__("x0") = a;
    register uptr x1 __asm__("x1") = b;
    register uptr x2 __asm__("x2") = c;
    register iptr x8 __asm__("x8") = nr;
    register uptr x3 __asm__("x3") = d, x4 __asm__("x4") = e, x5 __asm__("x5") = f;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8) : "memory", "cc");
    return (iptr)x0;
}
#else
#error The freestanding fixture needs a syscall and startup implementation for this host architecture.
#endif

static iptr systemCall(iptr nr, uptr a, uptr b, uptr c) {
    return systemCallArgs(nr,a,b,c,0,0,0);
}

static void output(const char* p, uptr n) {
    while (n) {
        iptr written = systemCall(NR_WRITE, 1, (uptr)p, n);
        if (written <= 0) systemCall(NR_EXIT, 70, 0, 0);
        p += written; n -= written;
    }
}
static void number(uptr n, unsigned base) {
    char buffer[32]; uptr count = 0;
    do { buffer[count++] = "0123456789abcdef"[n % base]; n /= base; } while (n);
    while (count) output(&buffer[--count], 1);
}
__attribute__((noinline, used)) static void fixtureWriter(void) { ++value; }
__attribute__((noinline, noclone, used)) static void fixtureBusyWait(volatile unsigned* counter) {
    while (spinning) if (counter) ++*counter;
}

__attribute__((noinline)) static void fixtureVectorSeed(void) {
    static const __UINT64_TYPE__ first[2] = {0x1111222233334444ULL, 0x5555666677778888ULL};
    static const __UINT64_TYPE__ last[2] = {0x9999aaaabbbbccccULL, 0xddddeeeeffff0000ULL};
#if defined(__x86_64__)
    __asm__ volatile("movdqu %0,%%xmm0\nmovdqu %1,%%xmm15" : : "m"(first), "m"(last) : "xmm0", "xmm15");
#elif defined(__i386__)
    /* This freestanding i386 fixture uses no compiler SIMD allocation. Its
       x86-64 host supplies SSE2 without needing a 32-bit runtime library. */
    __asm__ volatile("movdqu %0,%%xmm0\nmovdqu %1,%%xmm7" : : "m"(first), "m"(last));
#elif defined(__aarch64__)
    __asm__ volatile("ldr q0,%0\nldr q31,%1" : : "m"(first), "m"(last) : "v0", "v31");
#endif
}

__attribute__((noinline, used)) static uptr fixtureCallSum(
    uptr a,uptr b,uptr c,uptr d,uptr e,uptr f,uptr g,uptr h) {
#if defined(__x86_64__)
    __asm__ volatile("pxor %%xmm0,%%xmm0\npxor %%xmm15,%%xmm15" ::: "xmm0","xmm15");
#elif defined(__i386__)
    __asm__ volatile("pxor %xmm0,%xmm0\npxor %xmm7,%xmm7");
#else
    __asm__ volatile("movi v0.16b,#0\nmovi v31.16b,#0" ::: "v0","v31");
#endif
    __UINT64_TYPE__ mask=1ULL<<27; // Block SIGWINCH; the caller restores its mask.
    systemCallArgs(NR_SIGMASK,0,(uptr)&mask,0,8,0,0);
    return a+10*b+100*c+1000*d+10000*e+100000*f+1000000*g+10000000*h;
}
__attribute__((noinline, used)) static uptr fixtureCallWait(void) {
    callEntered=1;
    while (callWaiting) __asm__ volatile("" ::: "memory");
    return 73;
}
__attribute__((noinline, used)) static uptr fixtureCallFault(uptr address) {
    *(volatile unsigned*)address=1;
    return 99;
}
__attribute__((noinline, used)) static uptr fixtureCallCreate(uptr* handle) {
    *handle=(uptr)&callWaiting;
    return 0;
}
__attribute__((noinline, used)) static uptr fixtureCallDetach(uptr handle) {
    if (handle!=(uptr)&callWaiting) return 22;
    ++callDetached;
    return 0;
}
__attribute__((noinline, used)) static uptr fixtureCallSignal(void) {
    uptr pid=(uptr)systemCall(NR_GETPID,0,0,0);
    uptr tid=(uptr)systemCall(NR_GETTID,0,0,0);
    systemCall(NR_TGKILL,pid,tid,28);
    return 92;
}

#if defined(__aarch64__)
static char alternateStack[131072] __attribute__((aligned(16)));
struct FixtureStack { uptr sp; int flags; uptr size; };
_Static_assert(sizeof(struct FixtureStack)==24,"Linux AArch64 alternate-stack ABI");
static struct FixtureStack expectedStack;
static uptr expectedMask;
__attribute__((noinline)) static void fixtureStackSeed(void) {
    __asm__ volatile("sub sp,sp,#16384\nmov x16,sp\nmov x17,#2048\nmov x13,#0x5678\n"
        "1: str x13,[x16],#8\nsubs x17,x17,#1\nb.ne 1b\nadd sp,sp,#16384\n"
        ::: "memory", "cc", "x13", "x16", "x17");
}
__attribute__((noinline)) static void fixtureSveSeed(void) {
    __asm__ volatile(".arch_extension sve\n"
        "ptrue p0.b\nptrue p15.b\nsetffr\ndup z0.b,#0x12\ndup z31.b,#0x34\n"
        "mov x13,#0x08000000\nmsr fpsr,x13\nmov x13,#0x00400000\nmsr fpcr,x13\n"
        ::: "memory", "v0", "v31", "p0", "p15", "x13");
}
__attribute__((noinline)) static void fixtureSmeSeed(void) {
    __asm__ volatile(".arch_extension sme\nsmstart\n"
        "zero {za}\nptrue p0.b\nptrue p15.b\ndup z0.b,#0x56\ndup z31.b,#0x78\n"
        "mov w12,#0\nmova za0h.b[w12,0],p0/m,z0.b\n"
        "mov x13,#0x1234\nmsr tpidr2_el0,x13\nmov x13,#0x08000000\nmsr fpsr,x13\n"
        "mov x13,#0x00400000\nmsr fpcr,x13\n"
        ::: "memory", "v0", "v31", "p0", "p15", "x12", "x13");
}
static void fixtureVectorLoop(unsigned streaming) {
    spinning=1; heartbeat=0;
    output(streaming ? "CE_SME 0x" : "CE_SVE 0x",9); number((uptr)&spinning,16);
    output(" 0x",3); number((uptr)&heartbeat,16); output("\n",1);
    fixtureStackSeed();
    if (!streaming) fixtureSveSeed();
    else fixtureSmeSeed();
    fixtureBusyWait(&heartbeat);
    if (streaming) __asm__ volatile(".arch_extension sme\nsmstop\n" ::: "memory");
    output(streaming ? "CE_SME_DONE\n" : "CE_SVE_DONE\n",12);
}
static unsigned handlerStreaming;
static unsigned fixtureSmeControls=1;
static int fixtureScheduleVectors(void) {
    return systemCall(NR_PRCTL,50,16|(1u<<18),0)>=0 &&
        (!fixtureSmeControls || systemCall(NR_PRCTL,63,16|(1u<<18),0)>=0);
}
extern void fixtureSignalReturn(void);
static void fixtureVectorSignal(int signal) { (void)signal; fixtureVectorLoop(handlerStreaming); }
__asm__(".text\n.p2align 2\n.global fixtureSignalReturn\nfixtureSignalReturn:\nmov x8,#139\nsvc #0\n");
#endif

__attribute__((noreturn, used)) void fixtureMain(uptr* stack) {
    char** argv = (char**)&stack[1];
    const char* next = stack[0] > 1 ? argv[1] : (const char*)0;
    fixtureNext=next;
    /* Let independent CLI processes inspect this deliberately exposed test target. */
    systemCall(NR_PRCTL, 0x59616d61, (uptr)-1, 0); /* PR_SET_PTRACER, PR_SET_PTRACER_ANY */
    output("CE_TARGET ", 10); number(systemCall(NR_GETPID, 0, 0, 0), 10);
    output(" ", 1); number(sizeof(uptr), 10);
    output(" 0x", 3); number((uptr)&value, 16);
    output(" 0x", 3); number((uptr)&pointer, 16);
    output(" 0x", 3); number((uptr)fixtureWriter, 16);
    output(" 0x", 3); number((uptr)fixtureCallSite, 16);
    output(" 0x", 3); number((uptr)fixtureAfterCall, 16);
    output(" 0x", 3); number((uptr)fixtureReturnSite, 16);
    output(" 0x", 3); number((uptr)fixtureExitSite, 16);
    output(" 0x", 3); number((uptr)fixtureUserTrapSite, 16);
    output(" 0x", 3); number((uptr)fixtureExecSite, 16);
    output(" 0x", 3); number((uptr)fixtureSyscallSite, 16); output("\n", 1);
    char command;
    while (systemCall(NR_READ, 0, (uptr)&command, 1) == 1) {
        if (command == 'q') break;
        if (command == 'B') fixtureUserTrap();
        if (command == 'H') {
            siblingMode=3; siblingReady=0;
            number(fixtureSpawnThread(),10); output("\n",1); siblingReady=1;
        }
        if (command == 'g') { number(fixtureProbeSyscall(),10); output("\n",1); }
        if (command == 'j') {
            output("CE_FUNCTION 0x",14); number((uptr)fixtureCallSum,16);
            output(" 0x",3); number((uptr)fixtureCallWait,16);
            output(" 0x",3); number((uptr)fixtureCallFault,16);
            output(" 0x",3); number((uptr)&callWaiting,16);
            output(" 0x",3); number((uptr)&callEntered,16);
            output(" 0x",3); number((uptr)fixtureCallCreate,16);
            output(" 0x",3); number((uptr)fixtureCallDetach,16);
            output(" 0x",3); number((uptr)&callDetached,16);
            output(" 0x",3); number((uptr)fixtureCallSignal,16); output("\n",1);
        }
        if (command == 'S') {
            spinning=1; heartbeat=0;
            output("CE_CALL_BUSY 0x",15); number((uptr)&spinning,16);
            output(" 0x",3); number((uptr)&heartbeat,16); output("\n",1);
            fixtureVectorSeed(); fixtureBusyWait(&heartbeat);
            output("CE_CALL_DONE\n",13);
        }
        if (command == 'v') { fixtureVectorSeed(); output("CE_VECTORS\n", 11); }
        if (command == 's') {
            spinning = 1;
            output("CE_SPIN 0x", 10); number((uptr)&spinning, 16); output("\n", 1);
            while (spinning) __asm__ volatile("" ::: "memory");
        }
        if (command == 'u') {
            siblingMode=1; spinning=1; siblingReady=0; siblingDone=0; heartbeat=0;
            fixtureSpawnThread();
            while (!siblingReady) __asm__ volatile("" ::: "memory");
            output("CE_SHARED 0x",12); number((uptr)&spinning,16);
            output(" 0x",3); number((uptr)&heartbeat,16); output("\n",1);
            fixtureBusyWait((volatile unsigned*)0);
            while (!siblingDone) __asm__ volatile("" ::: "memory");
            siblingMode=0; output("CE_SHARED_DONE\n",15);
        }
#if defined(__aarch64__)
        if (command=='I') {
            // A separate declared profile, verified by the real kernel result.
            // The original profile retains both extension controls by default.
            if (systemCall(NR_PRCTL,64,0,0)==-22) {
                fixtureSmeControls=0;output("CE_SVE_ONLY_READY\n",18);
            } else output("CE_SVE_ONLY_FAILED\n",19);
        }
        if (command=='P') {
            struct sock_filter filter[]={
                BPF_STMT(BPF_LD|BPF_W|BPF_ABS,0),
                BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,139,0,1),
                BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|1),
                BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
            };
            struct sock_fprog program={4,filter};
            if (systemCall(NR_PRCTL,38,1,0)==0 && systemCall(NR_PRCTL,22,2,(uptr)&program)==0)
                output("CE_POLICY_READY\n",16);
            else output("CE_POLICY_FAILED\n",17);
        }
        if (command=='A' || command=='O') {
            expectedStack.sp=(uptr)alternateStack;
            expectedStack.flags=command=='O' ? (int)0x80000000u : 0;
            expectedStack.size=sizeof(alternateStack);
            expectedMask=(1u<<(10-1))|(1u<<(12-1));
            if (systemCall(132,(uptr)&expectedStack,0,0)==0 &&
                systemCallArgs(135,2,(uptr)&expectedMask,0,8,0,0)==0)
                output("CE_CONTEXT_READY\n",17);
            else output("CE_CONTEXT_FAILED\n",18);
        }
        if (command=='K') {
            struct FixtureStack actual={0}; uptr actualMask=0;
            if (systemCall(132,0,(uptr)&actual,0)==0 && systemCallArgs(135,2,0,(uptr)&actualMask,8,0,0)==0 &&
                actual.sp==expectedStack.sp && actual.size==expectedStack.size &&
                actual.flags==expectedStack.flags && actualMask==expectedMask)
                output("CE_CONTEXT_UNCHANGED\n",21);
            else output("CE_CONTEXT_CHANGED\n",19);
        }
        if (command=='L') {
            output("CE_LENGTHS ",11);
            number(systemCall(NR_PRCTL,51,0,0),10); output(" ",1);
            const iptr length=systemCall(NR_PRCTL,64,0,0);
            if (length<0) { output("-",1);number(0-(uptr)length,10); }
            else number(length,10);
            output("\n",1);
        }
        if (command=='Y' || command=='Z') {
            struct { uptr handler,flags,restorer,mask; } action={
                (uptr)fixtureVectorSignal,0x08000000u|0x04000000u,(uptr)fixtureSignalReturn,0
            };
            handlerStreaming=command=='Z';
            if (!fixtureScheduleVectors() ||
                systemCallArgs(134,14,(uptr)&action,0,8,0,0)<0)
                output("CE_HANDLER_FAILED\n",18);
            else {
                uptr pid=systemCall(NR_GETPID,0,0,0);
                systemCall(131,pid,pid,14);
            }
        }
        if (command=='E' || command=='F' || command=='M' || command=='N' || command=='V' || command=='W') {
            unsigned streaming=command=='M' || command=='N' || command=='W';
            if (systemCall(NR_PRCTL,streaming ? 64 : 51,0,0)<0 ||
                ((command=='F' || command=='N') && systemCall(NR_PRCTL,streaming ? 63 : 50,256,0)<0) ||
                ((command=='V' || command=='W') &&
                 !fixtureScheduleVectors())) {
                output("CE_EXTENSION_UNSUPPORTED\n",25);
                continue;
            }
            fixtureVectorLoop(streaming);
        }
#endif
#if defined(__x86_64__) || defined(__i386__)
        if (command == 'd' || command == 'D' || command == 'a' || command == 'n') {
            extern void fixtureDispatchSite(void), fixtureDispatchPost(void);
            spinning=1; heartbeat=0;
            dispatchSelector=command=='a' ? 0 : command=='D' ? 2 : 1;
            uptr offset=(uptr)fixtureDispatchPost,length=1;
            if (command=='a' || command=='n') { offset=0; length=0; }
            output("CE_DISPATCH 0x",14); number((uptr)&spinning,16);
            output(" 0x",3); number((uptr)&heartbeat,16);
            output(" 0x",3); number((uptr)&dispatchSelector,16);
            output(" 0x",3); number(offset,16);
            output(" 0x",3); number(length,16); output("\n",1);
            iptr result=systemCallArgs(NR_PRCTL,59,1,offset,length,(uptr)&dispatchSelector,0);
            if (!result) fixtureBusyWait(&heartbeat);
            dispatchSelector=0;
            if (!result) result=systemCallArgs(NR_PRCTL,59,0,0,0,0,0);
            if (!result) output("CE_DISPATCH_DONE\n",17);
            else output("CE_DISPATCH_FAILED\n",19);
        }
#endif
        if (command == 'f') {
            struct sock_filter rules[] = {
                {BPF_LD|BPF_W|BPF_ABS,0,0,0},
                {BPF_JMP|BPF_JEQ|BPF_K,0,1,NR_MAP},
                {BPF_RET|BPF_K,0,0,SECCOMP_RET_TRAP},
                {BPF_RET|BPF_K,0,0,SECCOMP_RET_ALLOW}
            };
            struct sock_fprog program = {4,rules};
            iptr result=systemCall(NR_PRCTL,38,1,0); /* PR_SET_NO_NEW_PRIVS */
            if (!result) result=systemCall(NR_PRCTL,22,2,(uptr)&program); /* PR_SET_SECCOMP, FILTER */
            if (!result) output("CE_FILTER_READY\n",16);
            else output("CE_FILTER_FAILED\n",17);
        }
        if (command == 'b') fixtureWriter();
        if (command == 'c') fixtureCaller();
        if (command == 't') fixtureSpawnThread();
        if (command == 'o') {
            siblingMode=4; spinning=1; heartbeat=0; siblingReady=0;
            __atomic_store_n(&ownerConsoleStage,0,__ATOMIC_RELEASE);
            __atomic_store_n(&ownerConsoleReady,0,__ATOMIC_RELEASE);
            iptr selected=fixtureSpawnThread();
            if (selected<=0) { output("CE_OWNER_FAILED\n",16); continue; }
            while (!__atomic_load_n(&siblingReady,__ATOMIC_ACQUIRE)) __asm__ volatile("" ::: "memory");
            __atomic_store_n(&ownerConsoleStage,1,__ATOMIC_RELEASE);
            iptr console=fixtureSpawnOnStack(ownerThreadStack+sizeof(ownerThreadStack));
            if (console<=0) { output("CE_OWNER_FAILED\n",16); continue; }
            while (!__atomic_load_n(&ownerConsoleReady,__ATOMIC_ACQUIRE)) __asm__ volatile("" ::: "memory");
            output("CE_OWNER_RECOVERY ",18);number((uptr)selected,10);output(" ",1);number((uptr)console,10);
            output(" 0x",3);number((uptr)&spinning,16);output(" 0x",3);number((uptr)&heartbeat,16);output("\n",1);
            fixtureExitThread();
        }
        if (command == 'l') {
            siblingMode=2;
            iptr tid=fixtureSpawnThread();
            if (tid<=0) { output("CE_LEADER_FAILED\n",17); continue; }
            while (!siblingReady) __asm__ volatile("" ::: "memory");
            number((uptr)tid,10); output("\n",1);
            fixtureExitThread();
        }
        if (command == 'r' || command == 'b' || command == 'c') { number(value, 10); output("\n", 1); }
        if (command == 'x' && next) {
            const char* args[] = {next, (const char*)0};
            const char* env[] = {(const char*)0};
            systemCall(NR_EXECVE, (uptr)next, (uptr)args, (uptr)env);
            output("EXEC_FAILED\n", 12);
        }
    }
    fixtureExitThread();
}

__attribute__((noreturn, used)) void fixtureThread(void) {
    if (siblingMode==4) {
        if (!__atomic_load_n(&ownerConsoleStage,__ATOMIC_ACQUIRE)) {
            __atomic_store_n(&siblingReady,1,__ATOMIC_RELEASE);
            fixtureBusyWait(&heartbeat);fixtureExitThread();
        }
        __atomic_store_n(&ownerConsoleReady,1,__ATOMIC_RELEASE);
    }
    if (siblingMode==3) {
        while (!siblingReady) __asm__ volatile("" ::: "memory");
        const char* args[]={fixtureNext,(const char*)0};
        const char* env[]={(const char*)0};
        fixtureExecThread(fixtureNext,args,env);
        output("EXEC_FAILED\n",12); fixtureExitThread();
    }
    if (siblingMode==2 || siblingMode==4) {
        siblingReady=1;
        char command;
        while (systemCall(NR_READ,0,(uptr)&command,1)==1) {
            if (command=='q') break;
            if (command=='b') fixtureWriter();
            if (command=='r' || command=='b') { number(value,10); output("\n",1); }
        }
        fixtureExitThread();
    }
    if (siblingMode) {
        siblingReady=1; fixtureBusyWait(&heartbeat); siblingDone=1;
        fixtureExitThread();
    }
    fixtureWriter(); number(value, 10); output("\n", 1);
    fixtureExitThread();
}

#if defined(__x86_64__)
__asm__(".global fixtureCaller,fixtureCallSite,fixtureAfterCall,fixtureReturnSite,fixtureSpawnThread\n"
        ".global fixtureExitThread,fixtureExitSite\nfixtureExitThread:\nmov $" FIXTURE_STRING(__NR_exit) ",%eax\nxor %edi,%edi\nfixtureExitSite:\nsyscall\nud2\n"
        ".global fixtureUserTrap,fixtureUserTrapSite,fixtureExecThread,fixtureExecSite,fixtureProbeSyscall,fixtureSyscallSite\n"
        "fixtureUserTrap:\nfixtureUserTrapSite:\nnop\nint3\nret\n"
        "fixtureExecThread:\nmov $" FIXTURE_STRING(__NR_execve) ",%eax\nfixtureExecSite:\nsyscall\nret\n"
        "fixtureProbeSyscall:\nmov $" FIXTURE_STRING(__NR_getpid) ",%eax\nfixtureSyscallSite:\nsyscall\nret\n"
        "fixtureDispatchDecoy:\nsyscall\nret\n"
        ".global fixtureDispatchSite,fixtureDispatchPost\nfixtureDispatchSite:\nsyscall\nfixtureDispatchPost:\nret\n"
        "fixtureCaller:\nsub $8,%rsp\nfixtureCallSite:\ncall fixtureWriter\n"
        "fixtureAfterCall:\nadd $8,%rsp\nfixtureReturnSite:\nret\n"
        ".global fixtureSpawnOnStack\nfixtureSpawnThread:\nlea threadStack+16384(%rip),%rdi\n"
        "fixtureSpawnOnStack:\nmov %rdi,%rsi\nmov $" FIXTURE_STRING(__NR_clone) ",%eax\nmov $0x50f00,%edi\n"
        "xor %edx,%edx\nxor %r10d,%r10d\nxor %r8d,%r8d\nsyscall\ntest %rax,%rax\njz 1f\nret\n"
        "1:\ncall fixtureThread\nud2\n");
#elif defined(__i386__)
__asm__(".global fixtureCaller,fixtureCallSite,fixtureAfterCall,fixtureReturnSite,fixtureSpawnThread\n"
        ".global fixtureExitThread,fixtureExitSite\nfixtureExitThread:\nmov $1,%eax\nxor %ebx,%ebx\nfixtureExitSite:\nint $0x80\nud2\n"
        ".global fixtureUserTrap,fixtureUserTrapSite,fixtureExecThread,fixtureExecSite,fixtureProbeSyscall,fixtureSyscallSite\n"
        "fixtureUserTrap:\nfixtureUserTrapSite:\nnop\nint3\nret\n"
        "fixtureExecThread:\npush %ebx\nmov 8(%esp),%ebx\nmov 12(%esp),%ecx\nmov 16(%esp),%edx\nmov $11,%eax\nfixtureExecSite:\nint $0x80\npop %ebx\nret\n"
        "fixtureProbeSyscall:\nmov $20,%eax\nfixtureSyscallSite:\nint $0x80\nret\n"
        "fixtureDispatchDecoy:\nint $0x80\nret\n"
        ".global fixtureDispatchSite,fixtureDispatchPost\nfixtureDispatchSite:\nint $0x80\nfixtureDispatchPost:\nret\n"
        "fixtureCaller:\nsub $12,%esp\nfixtureCallSite:\ncall fixtureWriter\n"
        "fixtureAfterCall:\nadd $12,%esp\nfixtureReturnSite:\nret\n"
        ".global fixtureSpawnOnStack\nfixtureSpawnThread:\nmov $threadStack+16384,%eax\njmp 2f\n"
        "fixtureSpawnOnStack:\nmov 4(%esp),%eax\n2:\npush %ebx\npush %esi\npush %edi\nmov %eax,%ecx\nmov $120,%eax\nmov $0x50f00,%ebx\n"
        "xor %edx,%edx\nxor %esi,%esi\nxor %edi,%edi\nint $0x80\n"
        "test %eax,%eax\njz 1f\npop %edi\npop %esi\npop %ebx\nret\n1:\ncall fixtureThread\nud2\n");
#elif defined(__aarch64__)
__asm__(".global fixtureCaller,fixtureCallSite,fixtureAfterCall,fixtureReturnSite,fixtureSpawnThread\n"
        ".global fixtureExitThread,fixtureExitSite\nfixtureExitThread:\nmov x8,#93\nmov x0,#0\nfixtureExitSite:\nsvc #0\nbrk #0\n"
        ".global fixtureUserTrap,fixtureUserTrapSite,fixtureExecThread,fixtureExecSite,fixtureProbeSyscall,fixtureSyscallSite\n"
        "fixtureUserTrap:\nfixtureUserTrapSite:\nnop\nbrk #0\nret\n"
        "fixtureExecThread:\nmov x8,#221\nfixtureExecSite:\nsvc #0\nret\n"
        "fixtureProbeSyscall:\nmov x8,#172\nfixtureSyscallSite:\nsvc #0\nret\n"
        "fixtureCaller:\nstp x29,x30,[sp,#-16]!\nmov x29,sp\nfixtureCallSite:\nbl fixtureWriter\n"
        "fixtureAfterCall:\nldp x29,x30,[sp],#16\nfixtureReturnSite:\nret\n"
        ".global fixtureSpawnOnStack\nfixtureSpawnThread:\nadrp x0,threadStack\nadd x0,x0,:lo12:threadStack\nadd x0,x0,#4,lsl #12\n"
        "fixtureSpawnOnStack:\nmov x1,x0\nmov x8,#220\nmov x0,#0xf00\nmovk x0,#5,lsl #16\n"
        "mov x2,#0\nmov x3,#0\nmov x4,#0\nsvc #0\ncbz x0,1f\nret\n1:\nb fixtureThread\n");
#endif

#if defined(__aarch64__)
__asm__(".global _start\n.type _start,%function\n_start:\nmov x0,sp\nb fixtureMain\n");
#else
__attribute__((naked, noreturn)) void _start(void) {
#if defined(__x86_64__)
    __asm__ volatile("mov %rsp,%rdi\n\tand $-16,%rsp\n\tcall fixtureMain\n\tud2");
#else
    __asm__ volatile("mov %esp,%eax\n\tand $-16,%esp\n\tpush %eax\n\tcall fixtureMain\n\tud2");
#endif
}
#endif
