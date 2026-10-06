#include <cerrno>
#include <cstdio>
#include <csignal>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/utsname.h>
#include <unistd.h>

int nativeCallIntegration(int argc,char** argv);

int main() {
    if (getpid()!=1 || (mount("proc","/proc","proc",0,nullptr) && errno!=EBUSY)) return 2;
    alarm(40);signal(SIGPIPE,SIG_IGN);
    utsname kernel{};
    if (!uname(&kernel)) printf("X32_CALL_KERNEL release=%s machine=%s\n",kernel.release,kernel.machine);
    printf("X32_CALL_PAGE_SIZE=%ld\n",sysconf(_SC_PAGESIZE));fflush(stdout);
    char program[]="x32_call_init",fixture[]="/native_call_fixture",library[]="/libnative_call_library.so";
    char* arguments[]={program,fixture,library,nullptr};
    const auto result=nativeCallIntegration(3,arguments);
    printf("X32_CALL_RESULT=%s\n",result ? "FAILED" : "PASSED");fflush(stdout);
    sync();reboot(RB_POWER_OFF);
    return result;
}
