#include "platform/linux/linux_process.hpp"
#include "core/autoasm.hpp"
#include <cstdio>
#include <cstdlib>
#include <sys/wait.h>
#include <unistd.h>
using namespace ce;
int main() {
 int input[2],output[2];if(pipe(input)||pipe(output)) return 2;
 auto child=fork();if(!child){dup2(input[0],0);dup2(output[1],1);close(input[1]);close(output[0]);execl("build/code_write_integration","code_write_integration","--fixture",nullptr);_exit(3);}
 close(input[0]);close(output[1]);FILE* replies=fdopen(output[0],"r");char text[256];unsigned long address=0;long pid=0;int value=0;
 if(!fgets(text,sizeof(text),replies)||sscanf(text,"CE_CODE_READY pid=%ld address=%lx value=%d",&pid,&address,&value)!=3) return 4;
 os::LinuxProcessHandle process(child);AutoAssembler assembler;
 char script[128];snprintf(script,sizeof(script),"[ENABLE]\n0x%lx:\nmov eax, 0x11\n",address);
 auto enable=assembler.execute(process,script);
 write(input[1],"X",1);if(!fgets(text,sizeof(text),replies))return 5;
 auto disable=assembler.disable(process,"[DISABLE]",enable.disableInfo);
 write(input[1],"E",1);if(!fgets(text,sizeof(text),replies))return 6;
 sscanf(text,"CE_CODE_VALUE=%d",&value);
 printf("UNDO_EXEC_PROBE enable=%d disable=%d replacementValue=%d error=%s\n",enable.success,disable.success,value,disable.error.c_str());fflush(stdout);
 write(input[1],"Q",1);int status;waitpid(child,&status,0);fclose(replies);close(input[1]);
 return enable.success && value==55 ? 0 : 1;
}
