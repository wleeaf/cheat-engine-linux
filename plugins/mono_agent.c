/* mono_agent.c — in-process Mono dissection agent (the Linux analog of CE's
 * MonoDataCollector). Loaded into a Mono/Unity target (LD_PRELOAD or the
 * loadlibrary() AA directive / injectLibrary), it resolves the Mono embedding
 * API from the already-loaded executable or a private runtime library without
 * changing symbol visibility or initializing a second runtime. It asks Mono for
 * ground truth the heuristic out-of-process scanner can't get: every loaded
 * image, its classes (namespace + name), and each field's REAL offset and type.
 *
 * Why in-process: field offsets and class layout are computed by the JIT at
 * load time; only the runtime knows them. Reading them out-of-process would mean
 * hard-coding version-specific MonoClass struct layouts. Asking mono_* is exact.
 *
 * Output: one line per record over a per-request Unix socket (host side parses it):
 *   IMG <image-name>
 *   CLS <Namespace>.<Name>
 *   FLD <offset> <S|-> <type-name> <field-name>      (S = static)
 * A leading "# ready" / "# error: …" line reports status.
 *
 * A detached native listener serves fresh dumps and method lookups after the
 * runtime initializes. Each request uses its own attached pthread and joins it
 * before replying, so managed and GC thread state finishes its TLS teardown.
 *
 * Build target: libcecore_mono_agent.so
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <limits.h>
#include "mono_protocol.h"

/* Opaque Mono types — we only pass pointers around. */
typedef void MonoDomain;
typedef void MonoThread;
typedef void MonoAssembly;
typedef void MonoImage;
typedef void MonoTableInfo;
typedef void MonoClass;
typedef void MonoClassField;
typedef void MonoType;

/* Mono embedding API, resolved by name at runtime. */
typedef MonoDomain* (*fn_get_root_domain)(void);
typedef int (*fn_runtime_is_shutting_down)(void);
typedef MonoThread* (*fn_thread_attach)(MonoDomain*);
typedef void (*fn_thread_detach)(MonoThread*);
typedef void (*fn_free)(void*);
typedef void        (*fn_assembly_foreach)(void (*)(void*, void*), void*);
typedef MonoImage*  (*fn_assembly_get_image)(MonoAssembly*);
typedef const char* (*fn_image_get_name)(MonoImage*);
typedef MonoTableInfo* (*fn_image_get_table_info)(MonoImage*, int);
typedef int         (*fn_table_info_get_rows)(const MonoTableInfo*);
typedef MonoClass*  (*fn_class_get)(MonoImage*, uint32_t);
typedef const char* (*fn_class_get_name)(MonoClass*);
typedef const char* (*fn_class_get_namespace)(MonoClass*);
typedef MonoClassField* (*fn_class_get_fields)(MonoClass*, void**);
typedef const char* (*fn_field_get_name)(MonoClassField*);
typedef uint32_t    (*fn_field_get_offset)(MonoClassField*);
typedef uint32_t    (*fn_field_get_flags)(MonoClassField*);
typedef MonoType*   (*fn_field_get_type)(MonoClassField*);
typedef char*       (*fn_type_get_name)(MonoType*);
typedef void*       (*fn_class_from_name)(MonoImage*, const char*, const char*);
typedef void*       (*fn_get_method_from_name)(MonoClass*, const char*, int);
typedef void*       (*fn_compile_method)(void* /*MonoMethod*/);

static struct {
    fn_get_root_domain     get_root_domain;
    fn_thread_attach       thread_attach;
    fn_thread_detach       thread_detach;
    fn_free                free_memory;
    fn_assembly_foreach    assembly_foreach;
    fn_assembly_get_image  assembly_get_image;
    fn_image_get_name      image_get_name;
    fn_image_get_table_info image_get_table_info;
    fn_table_info_get_rows table_info_get_rows;
    fn_class_get           class_get;
    fn_class_get_name      class_get_name;
    fn_class_get_namespace class_get_namespace;
    fn_class_get_fields    class_get_fields;
    fn_field_get_name      field_get_name;
    fn_field_get_offset    field_get_offset;
    fn_field_get_flags     field_get_flags;
    fn_field_get_type      field_get_type;
    fn_type_get_name       type_get_name;
    fn_class_from_name      class_from_name;
    fn_get_method_from_name get_method_from_name;
    fn_compile_method       compile_method;
} mono;

static FILE* g_out;

#define MONO_TABLE_TYPEDEF     0x02
#define MONO_TOKEN_TYPE_DEF    0x02000000u
#define FIELD_ATTRIBUTE_STATIC 0x0010

/* Each request borrows a reference to its actual runtime provider. Explicit
 * handles also see RTLD_LOCAL embeddings; never promote them to global scope
 * or load another runtime. Release the reference after the request thread exits. */
static void* g_exe;   /* dlopen(NULL) handle for the main program */
static void* g_runtime;
static void* resolve_sym(const char* sym) {
    if (g_runtime) return dlsym(g_runtime,sym);
    void* p = dlsym(RTLD_DEFAULT, sym);
    if (!p && g_exe) p = dlsym(g_exe, sym);
    return p;
}
static int find_runtime(struct dl_phdr_info* info,size_t size,void* data) {
    (void)size;(void)data;
    int main_program=!info->dlpi_name || !*info->dlpi_name;
    void* candidate=main_program ? g_exe : dlopen(info->dlpi_name,RTLD_LAZY|RTLD_NOLOAD);
    if (!candidate) return 0;
    void* root=dlsym(candidate,"mono_get_root_domain");
    if (root && dlsym(candidate,"mono_thread_attach") && dlsym(candidate,"mono_assembly_foreach")) {
        Dl_info provider;
        void* handle=NULL;
        if (dladdr(root,&provider) && provider.dli_fname)
            handle=dlopen(provider.dli_fname,RTLD_LAZY|RTLD_NOLOAD);
        if (!handle && main_program) {
            /* A statically linked mono-sgen executable cannot be dlopened by
             * filename. Prove that this symbol belongs to its own load ranges. */
            for (unsigned i=0;i<info->dlpi_phnum;++i) {
                if (info->dlpi_phdr[i].p_type!=PT_LOAD) continue;
                uintptr_t start=info->dlpi_addr+info->dlpi_phdr[i].p_vaddr;
                uintptr_t end=start+info->dlpi_phdr[i].p_memsz;
                if (end>=start && (uintptr_t)root>=start && (uintptr_t)root<end) {
                    handle=g_exe;break;
                }
            }
        }
        if (handle) {
            g_runtime=handle;
            mono.get_root_domain=(fn_get_root_domain)dlsym(handle,"mono_get_root_domain");
        }
    }
    if (!main_program) dlclose(candidate);
    return g_runtime!=NULL;
}
static void acquire_runtime(void) {
    /* Cached API pointers become invalid when an embedded owner dlcloses its
     * runtime between requests. Discover and resolve them afresh each time. */
    memset(&mono,0,sizeof(mono));
    dl_iterate_phdr(find_runtime,NULL);
}
static void release_runtime(void) {
    if (g_runtime && g_runtime!=g_exe) dlclose(g_runtime);
    g_runtime=NULL;
    memset(&mono,0,sizeof(mono));
}

/* Resolve the remaining API inside the provider acquired for this request.
 * Hard-fail only on the functions
 * without which enumeration is impossible; names are best-effort. Returns a
 * missing REQUIRED symbol, or NULL. */
static const char* resolve_rest(void) {
    #define REQUIRE(field, sym) do { \
        mono.field = (void*)resolve_sym(sym); \
        if (!mono.field) return sym; \
    } while (0)
    #define OPTIONAL(field, sym) mono.field = (void*)resolve_sym(sym)

    REQUIRE(thread_attach,       "mono_thread_attach");
    REQUIRE(thread_detach,       "mono_thread_detach");
    REQUIRE(assembly_foreach,    "mono_assembly_foreach");
    REQUIRE(assembly_get_image,  "mono_assembly_get_image");
    REQUIRE(image_get_table_info,"mono_image_get_table_info");
    REQUIRE(table_info_get_rows, "mono_table_info_get_rows");
    REQUIRE(class_get,           "mono_class_get");
    REQUIRE(class_get_fields,    "mono_class_get_fields");
    REQUIRE(field_get_offset,    "mono_field_get_offset");

    OPTIONAL(image_get_name,      "mono_image_get_name");
    OPTIONAL(class_get_name,      "mono_class_get_name");
    OPTIONAL(class_get_namespace, "mono_class_get_namespace");
    OPTIONAL(field_get_name,      "mono_field_get_name");
    OPTIONAL(field_get_flags,     "mono_field_get_flags");
    OPTIONAL(field_get_type,      "mono_field_get_type");
    OPTIONAL(free_memory,         "mono_free");
    mono.type_get_name = (fn_type_get_name)resolve_sym("mono_type_get_name");
    if (!mono.type_get_name)
        mono.type_get_name = (fn_type_get_name)resolve_sym("mono_type_full_name");
    if (!mono.free_memory) mono.type_get_name = NULL;
    // For findMonoFunction (targeted method resolution — no mass compilation).
    OPTIONAL(class_from_name,      "mono_class_from_name");
    OPTIONAL(get_method_from_name, "mono_class_get_method_from_name");
    OPTIONAL(compile_method,       "mono_compile_method");
    #undef REQUIRE
    #undef OPTIONAL
    return NULL;
}

// ── findMonoFunction RPC: resolve + JIT-compile ONE named method on demand ──
// Only the requested method is compiled (mono_compile_method returns the existing
// address if already JIT'd), so this never mass-compiles the target.
static const char* g_reqNs;
static const char* g_reqCls;
static void* g_foundClass;
static void find_class_cb(void* assembly, void* ud) {
    (void)ud;
    if (g_foundClass || !mono.class_from_name) return;
    MonoImage* img = mono.assembly_get_image(assembly);
    if (!img) return;
    void* k = mono.class_from_name(img, g_reqNs && *g_reqNs ? g_reqNs : "", g_reqCls);
    if (k) g_foundClass = k;
}
static void* resolve_method(const char* ns, const char* cls, const char* meth, int paramCount) {
    if (!mono.class_from_name || !mono.get_method_from_name || !mono.compile_method) return NULL;
    g_reqNs = ns; g_reqCls = cls; g_foundClass = NULL;
    mono.assembly_foreach(find_class_cb, NULL);
    if (!g_foundClass) return NULL;
    void* m = mono.get_method_from_name(g_foundClass, meth, paramCount);
    if (!m) return NULL;
    return mono.compile_method(m);
}

static void dump_class(MonoClass* klass) {
    if (!klass || ferror(g_out)) return;
    const char* ns   = mono.class_get_namespace ? mono.class_get_namespace(klass) : "";
    const char* name = mono.class_get_name ? mono.class_get_name(klass) : "?";
    fprintf(g_out, "CLS %s.%s\n", ns && *ns ? ns : "", name ? name : "?");

    void* iter = NULL;
    MonoClassField* f;
    while (!ferror(g_out) && (f = mono.class_get_fields(klass, &iter))) {
        const char* fname = mono.field_get_name ? mono.field_get_name(f) : "?";
        uint32_t off = mono.field_get_offset(f);
        int is_static = 0;
        if (mono.field_get_flags)
            is_static = (mono.field_get_flags(f) & FIELD_ATTRIBUTE_STATIC) != 0;
        char* tn = NULL;
        MonoType* ft = mono.field_get_type ? mono.field_get_type(f) : NULL;
        if (ft && mono.type_get_name) tn = mono.type_get_name(ft);
        fprintf(g_out, "FLD 0x%x %c %s %s\n", off, is_static ? 'S' : '-',
                tn ? tn : "?", fname ? fname : "?");
        if (tn) mono.free_memory(tn);
    }
}

static void on_assembly(void* assembly, void* user_data) {
    (void)user_data;
    if (ferror(g_out)) return;
    MonoImage* img = mono.assembly_get_image(assembly);
    if (!img) return;
    const char* iname = mono.image_get_name ? mono.image_get_name(img) : NULL;
    fprintf(g_out, "IMG %s\n", iname ? iname : "?");

    MonoTableInfo* t = mono.image_get_table_info(img, MONO_TABLE_TYPEDEF);
    if (!t) return;
    int rows = mono.table_info_get_rows(t);
    /* Typedef tokens are 1-based; row 1 is the <Module> pseudo-class. */
    for (int i = 1; i <= rows && !ferror(g_out); ++i) {
        MonoClass* klass = mono.class_get(img, MONO_TOKEN_TYPE_DEF | (uint32_t)i);
        dump_class(klass);
    }
}

static int64_t now_ms(void) {
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC,&value);
    return (int64_t)value.tv_sec*1000+value.tv_nsec/1000000;
}
static int transfer(int fd, void* bytes, size_t size, int sending) {
    size_t done=0;
    int64_t deadline=now_ms()+3000;
    while (done<size) {
        int64_t remaining=deadline-now_ms();
        if (remaining<=0) return 0;
        struct pollfd poller={fd,sending ? POLLOUT : POLLIN,0};
        int result=poll(&poller,1,(int)remaining);
        if (result<0 && errno==EINTR) continue;
        if (result<=0) return 0;
        ssize_t count=sending ? send(fd,(char*)bytes+done,size-done,MSG_NOSIGNAL|MSG_DONTWAIT) :
            recv(fd,(char*)bytes+done,size-done,MSG_DONTWAIT);
        if (count<0 && (errno==EINTR || errno==EAGAIN)) continue;
        if (count<=0) return 0;
        done+=(size_t)count;
    }
    return 1;
}
static void respond(int fd, unsigned status, const char* payload, size_t length) {
    if (length>CE_MONO_MAX_RESPONSE) {
        payload="Mono metadata response exceeds the protocol memory bound";
        length=strlen(payload);status=CE_MONO_ERROR;
    }
    uint32_t header[]={htonl(CE_MONO_MAGIC),htonl(status),htonl((uint32_t)length)};
    if (transfer(fd,header,sizeof(header),1)) transfer(fd,(void*)payload,length,1);
}
struct RuntimeJob {
    unsigned command;int32_t count;
    char *ns,*cls,*method,*payload;
    size_t payloadSize,capacity;
    int limitReached;
    unsigned status;
    MonoDomain* domain;
};
/* Bound allocation during generation, rather than after open_memstream has
 * already accumulated an arbitrarily large metadata dump in the application. */
static ssize_t write_payload(void* data,const char* bytes,size_t size) {
    struct RuntimeJob* job=data;
    if (size>CE_MONO_MAX_RESPONSE-job->payloadSize) {
        job->limitReached=1;errno=EFBIG;return -1;
    }
    size_t required=job->payloadSize+size+1;
    if (required>job->capacity) {
        size_t capacity=job->capacity ? job->capacity : 4096;
        const size_t maximum=(size_t)CE_MONO_MAX_RESPONSE+1;
        if (capacity>maximum) capacity=maximum;
        while (capacity<required) capacity=capacity>maximum/2 ? maximum : capacity*2;
        char* payload=realloc(job->payload,capacity);
        if (!payload) return -1;
        job->payload=payload;job->capacity=capacity;
    }
    memcpy(job->payload+job->payloadSize,bytes,size);
    job->payloadSize+=size;job->payload[job->payloadSize]=0;
    return (ssize_t)size;
}
static void* runtime_request(void* data) {
    struct RuntimeJob* job=data;
    MonoThread* thread=mono.thread_attach(job->domain);
    if (!thread) return NULL;
    cookie_io_functions_t output={.write=write_payload};
    FILE* stream=fopencookie(job,"w",output);
    if (stream) {
        setvbuf(stream,NULL,_IONBF,0);
        if (job->command==CE_MONO_DUMP) {
            g_out=stream;
            mono.assembly_foreach(on_assembly,NULL);
            fprintf(stream,"# done\n");g_out=NULL;
        } else {
            void* address=resolve_method(job->ns,job->cls,job->method,job->count);
            fprintf(stream,"%zx\n",(size_t)address);
        }
        int failed=ferror(stream);
        if (fclose(stream)) failed=1;
        job->status=failed ? CE_MONO_ERROR : CE_MONO_OK;
    }
    mono.thread_detach(thread);
    /* Mono 6.x's public detach removes the managed thread but leaves its
     * low-level GC thread record until pthread TLS teardown. End the pthread
     * and join it before publishing a response or returning to socket I/O. */
    return NULL;
}
static void serve_request(int fd) {
    uint32_t header[6];
    if (!transfer(fd,header,sizeof(header),0)) return;
    for (unsigned i=0;i<6;++i) header[i]=ntohl(header[i]);
    uint64_t length=(uint64_t)header[2]+header[3]+header[4];
    if (header[0]!=CE_MONO_MAGIC || length>CE_MONO_MAX_REQUEST ||
        (header[1]!=CE_MONO_DUMP && header[1]!=CE_MONO_METHOD) ||
        (header[1]==CE_MONO_DUMP && length) ||
        (header[1]==CE_MONO_METHOD && header[5]>INT32_MAX && header[5]!=UINT32_MAX)) {
        respond(fd,CE_MONO_ERROR,"Invalid Mono request",20);return;
    }
    char* args=calloc((size_t)length+3,1);
    if (!args) { respond(fd,CE_MONO_ERROR,"Mono request allocation failed",30);return; }
    char* ns=args;
    char* cls=ns+header[2]+1;
    char* method=cls+header[3]+1;
    if (!transfer(fd,ns,header[2],0) || !transfer(fd,cls,header[3],0) ||
        !transfer(fd,method,header[4],0) || memchr(ns,0,header[2]) ||
        memchr(cls,0,header[3]) || memchr(method,0,header[4])) { free(args);return; }
    acquire_runtime();
    fn_runtime_is_shutting_down shutting_down=mono.get_root_domain ?
        (fn_runtime_is_shutting_down)resolve_sym("mono_runtime_is_shutting_down") : NULL;
    if (shutting_down && shutting_down()) {
        const char* message="Mono runtime is shutting down";
        respond(fd,CE_MONO_ERROR,message,strlen(message));goto finished;
    }
    MonoDomain* domain=mono.get_root_domain ? mono.get_root_domain() : NULL;
    if (!domain) {
        respond(fd,CE_MONO_ERROR,"Mono root domain is unavailable",31);goto finished;
    }
    const char* missing=resolve_rest();
    if (missing) { respond(fd,CE_MONO_ERROR,missing,strlen(missing));goto finished; }
    struct RuntimeJob job={.command=header[1],.ns=ns,.cls=cls,.method=method,
        .status=CE_MONO_ERROR,.domain=domain};
    uint32_t bits=header[5];memcpy(&job.count,&bits,sizeof(bits));
    pthread_t handler;
    int launched=pthread_create(&handler,NULL,runtime_request,&job)==0;
    if (launched) pthread_join(handler,NULL);
    if (job.limitReached) {
        const char* message="Mono metadata response exceeds the protocol memory bound";
        respond(fd,CE_MONO_ERROR,message,strlen(message));
    } else if (job.status==CE_MONO_OK && job.payload) respond(fd,job.status,job.payload,job.payloadSize);
    else respond(fd,CE_MONO_ERROR,"Mono runtime request failed",27);
    free(job.payload);
finished:
    release_runtime();
    free(args);
}
static void* worker(void* arg) {
    (void)arg;
    char directory[64];struct sockaddr_un address={.sun_family=AF_UNIX};
    snprintf(directory,sizeof(directory),"/tmp/cecore_mono_%d",(int)getpid());
    if (mkdir(directory,0700)<0 && errno!=EEXIST) return NULL;
    struct stat info;
    if (lstat(directory,&info)<0 || !S_ISDIR(info.st_mode) || info.st_uid!=geteuid() ||
        (info.st_mode&0777)!=0700) return NULL;
    snprintf(address.sun_path,sizeof(address.sun_path),"%s/agent.sock",directory);
    int listener=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
    if (listener<0) return NULL;
    unlink(address.sun_path);
    if (bind(listener,(struct sockaddr*)&address,sizeof(address))<0 || listen(listener,16)<0) {
        close(listener);return NULL;
    }
    g_exe=dlopen(NULL,RTLD_LAZY);
    for (;;) {
        int client=accept4(listener,NULL,NULL,SOCK_CLOEXEC);
        if (client<0) { if (errno==EINTR) continue;break; }
        struct ucred peer;socklen_t length=sizeof(peer);
        if (getsockopt(client,SOL_SOCKET,SO_PEERCRED,&peer,&length)==0 &&
            (peer.uid==geteuid() || peer.uid==0)) serve_request(client);
        close(client);
    }
    close(listener);unlink(address.sun_path);
    if (g_exe) dlclose(g_exe);
    return NULL;
}

__attribute__((constructor))
static void mono_agent_init(void) {
    pthread_t th;
    if (pthread_create(&th, NULL, worker, NULL) == 0)
        pthread_detach(th);
}
