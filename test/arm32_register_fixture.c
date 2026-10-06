#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <unistd.h>

volatile unsigned arm32_resume_word;
volatile sig_atomic_t arm32_application_signal_word;
static void application_handler(int signal) { (void)signal; ++arm32_application_signal_word; }
static void resume_handler(int signal) { (void)signal; arm32_resume_word = 1; }
extern unsigned arm32_work(void), thumb32_work(void);
extern char arm32_work_end[], thumb32_work_end[], arm32_trap_site[], thumb32_trap_site[];

__asm__(
    ".syntax unified\n.arch armv7-a\n.fpu neon\n.text\n.arm\n.align 2\n"
    ".global arm32_work\n.type arm32_work,%function\narm32_work:\n"
    "push {r4-r11,lr}\n"
    "ldr r4,=0x12345678\nldr r5,=0x9abcdef0\nvmov d8,r4,r5\n"
    "ldr r4,=0x76543210\nldr r5,=0xfedcba98\nvmov d31,r4,r5\n"
    "mov r4,#0x00400000\nvmsr fpscr,r4\nldr r8,=0x89abcdef\nldr r9,=0xf1234567\nldr r11,=0x11223344\n"
    "ldr r1,=arm32_resume_word\n.global arm32_trap_site\narm32_trap_site:\nnop\n"
    "ldr r2,[r1]\ncmp r2,#0\nbeq arm32_trap_site\nmov r0,r8\npop {r4-r11,pc}\n"
    ".global arm32_work_end\narm32_work_end:\n.ltorg\n"
    ".thumb\n.align 1\n.global thumb32_work\n.type thumb32_work,%function\n.thumb_func\nthumb32_work:\n"
    "push {r4-r11,lr}\n"
    "ldr r4,=0x12345678\nldr r5,=0x9abcdef0\nvmov d8,r4,r5\n"
    "ldr r4,=0x76543210\nldr r5,=0xfedcba98\nvmov d31,r4,r5\n"
    "mov r4,#0x00400000\nvmsr fpscr,r4\nldr r8,=0x89abcdef\nldr r9,=0xf1234567\nldr r11,=0x11223344\n"
    "ldr r1,=arm32_resume_word\nthumb32_loop:\nldr r2,[r1]\ncmp r2,#0\nite eq\n"
    ".global thumb32_trap_site\nthumb32_trap_site:\nnopeq\nnopne\n"
    "beq thumb32_loop\nmov r0,r8\npop {r4-r11,pc}\n"
    ".global thumb32_work_end\nthumb32_work_end:\n.ltorg\n"
);

int main(int argc, char** argv) {
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    signal(SIGUSR1, resume_handler);
    signal(SIGUSR2, application_handler);
    void* scratch=mmap(0,4096,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    const int file=memfd_create("arm32-offset-fixture",0);
    const uint64_t marker=UINT64_C(0x445566778899aabb),offset=UINT64_C(6)*1024*1024*1024;
    if (scratch==MAP_FAILED || file<0 || ftruncate(file,(off_t)(offset+4096)) ||
        pwrite(file,&marker,sizeof(marker),(off_t)offset)!=sizeof(marker)) return 2;
    for (unsigned i=0;i<4096;++i) ((unsigned char*)scratch)[i]=(unsigned char)(31+17*i);
    const int thumb = argc == 2 && !strcmp(argv[1], "thumb");
    unsigned (*work)(void) = thumb ? thumb32_work : arm32_work;
    printf("ARM32_FIXTURE %s %ld %lx %lx %lx %lx %d %lx\n", thumb ? "THUMB" : "ARM", (long)getpid(),
           (unsigned long)((uintptr_t)work & ~(uintptr_t)1),
           (unsigned long)(uintptr_t)(thumb ? thumb32_work_end : arm32_work_end),
           (unsigned long)(uintptr_t)(thumb ? thumb32_trap_site : arm32_trap_site),
           (unsigned long)(uintptr_t)scratch,file,(unsigned long)(uintptr_t)&arm32_application_signal_word);
    fflush(stdout);
    const unsigned result = work();
    uint64_t d8, d31; unsigned fpscr;
    __asm__ volatile("vmov %Q0, %R0, d8" : "=r"(d8));
    __asm__ volatile("vmov %Q0, %R0, d31" : "=r"(d31));
    __asm__ volatile("vmrs %0, fpscr" : "=r"(fpscr));
    printf("ARM32_CHILD %u\n", result);
    printf("ARM32_VFP_CHILD %llu %llu %u\n", (unsigned long long)d8, (unsigned long long)d31, fpscr);
    fflush(stdout);
    munmap(scratch,4096); close(file);
    return 0;
}
