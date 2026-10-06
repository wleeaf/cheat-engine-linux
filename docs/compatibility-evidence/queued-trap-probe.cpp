#include "debug/code_finder.hpp"
#include "debug/debug_session.hpp"
#include "platform/linux/linux_process.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
using namespace ce;
struct alignas(64) Stats {volatile unsigned value=0,traps=0;volatile int code=0;volatile uintptr_t address=0;};
static Stats stats;
static std::atomic<int> phase{0};
extern "C" long ptrace(enum __ptrace_request request,...) noexcept {
 va_list a;va_start(a,request);pid_t pid=va_arg(a,pid_t);void* addr=va_arg(a,void*);void* data=va_arg(a,void*);va_end(a);
 using Fn=long(*)(enum __ptrace_request,...);static Fn original=(Fn)dlsym(RTLD_NEXT,"ptrace");
 if(request==PTRACE_POKEUSER && (uintptr_t)addr==offsetof(struct user,u_debugreg)+7*sizeof(unsigned long) && !data) {
  int saved=errno;long dr6=original(PTRACE_PEEKUSER,pid,(void*)(offsetof(struct user,u_debugreg)+6*sizeof(unsigned long)),nullptr);
  fprintf(stderr,"DISABLE phase=%d tid=%d DR6=%lx\n",phase.load(),pid,dr6);errno=saved;
 }
 if(request==PTRACE_DETACH) {
  int saved=errno;siginfo_t si{};long info=original(PTRACE_GETSIGINFO,pid,nullptr,&si);
  struct {uint64_t offset;uint32_t flags;int32_t count;} args{0,0,8};siginfo_t pending[8]{};
  long n=original(PTRACE_PEEKSIGINFO,pid,&args,pending);
  fprintf(stderr,"DETACH phase=%d tid=%d sig=%ld info=%ld code=%d addr=%p pending=%ld\n",phase.load(),pid,(long)data,info,si.si_code,si.si_addr,n);
  for(long i=0;i<n;++i)fprintf(stderr,"QUEUED signo=%d code=%d addr=%p\n",pending[i].si_signo,pending[i].si_code,pending[i].si_addr);
  errno=saved;
 }
 long result=original(request,pid,addr,data);int saved=errno;
 if(request==PTRACE_PEEKSIGINFO && result>0){auto* infos=(siginfo_t*)data;for(long i=0;i<result;++i)if(infos[i].si_signo==SIGTRAP)fprintf(stderr,"PEEK_QUEUE phase=%d code=%d addr=%p\n",phase.load(),infos[i].si_code,infos[i].si_addr);}
 if(request==PTRACE_CONT && data)fprintf(stderr,"DELIVER phase=%d tid=%d sig=%ld result=%ld\n",phase.load(),pid,(long)data,result);
 errno=saved;return result;
}
static void trap(int,siginfo_t* si,void*) {stats.traps=stats.traps+1;stats.code=si->si_code;stats.address=(uintptr_t)si->si_addr;}
int main(int argc,char** argv) {
 alarm(90);int ready[2];if(pipe(ready))return 2;auto parent=getpid();pid_t child=fork();
 if(!child){prctl(PR_SET_PDEATHSIG,SIGKILL);if(getppid()!=parent)_exit(2);close(ready[0]);struct sigaction action{};action.sa_sigaction=trap;action.sa_flags=SA_SIGINFO;sigaction(SIGTRAP,&action,nullptr);char c='R';if(write(ready[1],&c,1)!=1)_exit(3);close(ready[1]);for(;;){stats.value=stats.value+1;usleep(1000);}}
 close(ready[1]);char c;if(read(ready[0],&c,1)!=1)return 3;close(ready[0]);
 os::LinuxProcessHandle process(child);os::LinuxDebugger debugger;CodeFinder finder;
 unsigned rounds=argc>1 ? strtoul(argv[1],nullptr,10) : 100;bool ok=true;
 for(unsigned i=0;i<rounds;++i){
  phase=1;bool started=finder.start(process,debugger,(uintptr_t)&stats.value,true,4,false,false);if(!started){printf("START_FAIL %u %s\n",i,finder.lastError().message().c_str());ok=false;break;}
  usleep(i%5==4 ? 40000 : i%5*1000);phase=2;finder.stop();usleep(2000);
  Stats after{};auto read=process.read((uintptr_t)&stats,&after,sizeof(after));
  if(!read || after.traps){printf("FINDER_FAILURE round=%u traps=%u code=%d address=%lx\n",i,after.traps,after.code,after.address);fflush(stdout);ok=false;break;}
  if(argc<=2 || strcmp(argv[2],"finder")){
   phase=3;DebugSession session;bool attached=session.attach(child,&process);phase=4;session.detach();usleep(2000);
   read=process.read((uintptr_t)&stats,&after,sizeof(after));
   if(!attached || !read || after.traps){printf("SESSION_FAILURE round=%u attached=%d traps=%u code=%d address=%lx\n",i,attached,after.traps,after.code,after.address);fflush(stdout);ok=false;break;}
  }
  if(i%20==0){printf("ROUND=%u\n",i);fflush(stdout);}
 }
 kill(child,SIGKILL);int status;while(waitpid(child,&status,0)<0 && errno==EINTR){}
 printf("TEARDOWN_RESULT=%s\n",ok ? "PASSED" : "FAILED");return ok ? 0 : 1;
}
