#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Real Mono embedding with private loader scope. No Mono headers or link-time
 * dependency are needed; the gate supplies the actual runtime library. */
typedef void* (*init_fn)(const char*,const char*);
typedef void* (*assembly_fn)(void*,const char*);
typedef int (*exec_fn)(void*,void*,int,char**);
typedef void (*cleanup_fn)(void*);
typedef void (*dirs_fn)(const char*,const char*);
typedef void (*config_fn)(const char*);
typedef int (*shutdown_fn)(void);
static volatile uint32_t waiting;

int main(int argc,char** argv) {
    if (argc!=6) return 2;
    void* runtime=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
    if (!runtime) { fprintf(stderr,"MONO_EMBED_ERROR %s\n",dlerror());return 3; }
    init_fn init=(init_fn)dlsym(runtime,"mono_jit_init_version");
    assembly_fn assembly_open=(assembly_fn)dlsym(runtime,"mono_domain_assembly_open");
    exec_fn execute=(exec_fn)dlsym(runtime,"mono_jit_exec");
    cleanup_fn cleanup=(cleanup_fn)dlsym(runtime,"mono_jit_cleanup");
    dirs_fn set_dirs=(dirs_fn)dlsym(runtime,"mono_set_dirs");
    config_fn configure=(config_fn)dlsym(runtime,"mono_config_parse");
    shutdown_fn is_shutting_down=(shutdown_fn)dlsym(runtime,"mono_runtime_is_shutting_down");
    if (!init || !assembly_open || !execute || !cleanup || !set_dirs || !configure || !is_shutting_down) return 4;
    if (dlsym(RTLD_DEFAULT,"mono_get_root_domain")) {
        fprintf(stderr,"MONO_EMBED_ERROR runtime symbols were not private\n");return 5;
    }
    fprintf(stderr,"MONO_EMBED_LOCAL_EXPORTS=hidden\n");
    set_dirs(argv[4],argv[5]);
    configure(NULL);
    void* domain=init("cecompat-embedded","v4.0.30319");
    if (!domain) return 6;
    void* assembly=assembly_open(domain,argv[2]);
    if (!assembly) return 7;
    int result=execute(domain,assembly,2,argv+2);
    if (dlsym(RTLD_DEFAULT,"mono_get_root_domain")) {
        fprintf(stderr,"MONO_EMBED_ERROR agent promoted the runtime's loader scope\n");return 8;
    }
    cleanup(domain);
    int stopped=is_shutting_down();
    fprintf(stderr,"MONO_EMBED_AFTER_CLEANUP_SHUTTING_DOWN=%d\n",stopped);
    if (!stopped) return 9;
    waiting=1;
    printf("MONO_CLEANED_READY %d %p\n",(int)getpid(),(void*)&waiting);
    fflush(stdout);
    while (waiting) __asm__ volatile("" ::: "memory");
    dlclose(runtime);
    void* resident=dlopen(argv[1],RTLD_LAZY|RTLD_NOLOAD);
    fprintf(stderr,"MONO_EMBED_RUNTIME_AFTER_OWNER_CLOSE=%s\n",resident ? "resident" : "unloaded");
    if (resident) dlclose(resident);
    fprintf(stderr,"MONO_EMBED_LOCAL_EXPORTS_AFTER_REQUESTS=hidden\n");
    waiting=1;
    printf("MONO_SHUTDOWN_READY %d %p\n",(int)getpid(),(void*)&waiting);
    fflush(stdout);
    while (waiting) __asm__ volatile("" ::: "memory");
    puts("MONO_EMBED_EXIT");
    fflush(stdout);
    return result;
}
