#include "platform/linux/linux_process.hpp"
#include "platform/linux/memory_image.hpp"
#include <cstdio>
#include <cstdlib>
#include <sys/wait.h>
#include <unistd.h>
using namespace ce;
int main() {
 int commands[2],responses[2];if(pipe(commands)||pipe(responses))return 2;
 auto child=fork();if(!child){dup2(commands[0],0);dup2(responses[1],1);close(commands[1]);close(responses[0]);execl("build/.ci-tmp/shared_mm_fixture","shared_mm_fixture",nullptr);_exit(3);}
 close(commands[0]);close(responses[1]);FILE* replies=fdopen(responses[0],"r");char line[256];
 if(!fgets(line,sizeof(line),replies))return 4;
 os::LinuxProcessHandle process(child);auto saved=os::pinNativeMemoryImage(process);if(!saved||!*saved)return 5;
 write(commands[1],"X",1);if(!fgets(line,sizeof(line),replies))return 6;
 const auto alive=(*saved)->check();
 auto changed=(*saved)->protect(0x30000000,8,MemProt::ReadWrite);auto code=process.queryRegion(0x30000000);
 const bool protectSafe=!changed && changed.error()==std::errc::operation_canceled && code && code->protection==(MemProt::Read|MemProt::Exec);
 process.protect(0x30000000,8,MemProt::Read|MemProt::Exec);
 auto freed=(*saved)->free(0x31000000,4096);const bool freeSafe=!freed && freed.error()==std::errc::operation_canceled && process.queryRegion(0x31000000).has_value();
 auto allocated=(*saved)->allocate(4096,MemProt::ReadWrite,0x32000000);const bool allocateSafe=!allocated && allocated.error()==std::errc::operation_canceled && !process.queryRegion(0x32000000);
 if(allocated)process.free(*allocated,4096);
 write(commands[1],"E",1);if(!fgets(line,sizeof(line),replies))return 7;
 printf("SHARED_MM_PROBE oldAlive=%d protect=%d free=%d allocate=%d replacement=%s",bool(alive),protectSafe,freeSafe,allocateSafe,line);fflush(stdout);
 write(commands[1],"Q",1);int status=0;waitpid(child,&status,0);fclose(replies);close(commands[1]);
 return alive && protectSafe && freeSafe && allocateSafe && WIFEXITED(status) && !WEXITSTATUS(status) ? 0 : 1;
}
