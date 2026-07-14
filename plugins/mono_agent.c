/* mono_agent.c — in-process Mono dissection agent (the Linux analog of CE's
 * MonoDataCollector). Loaded into a Mono/Unity target (LD_PRELOAD or the
 * loadlibrary() AA directive / injectLibrary), it resolves the Mono embedding
 * API from the already-loaded runtime via dlsym(RTLD_DEFAULT, …) — the mono_*
 * symbols live in the mono-sgen executable — and asks Mono itself for the
 * ground truth the heuristic out-of-process scanner can't get: every loaded
 * image, its classes (namespace + name), and each field's REAL offset and type.
 *
 * Why in-process: field offsets and class layout are computed by the JIT at
 * load time; only the runtime knows them. Reading them out-of-process would mean
 * hard-coding version-specific MonoClass struct layouts. Asking mono_* is exact.
 *
 * Output: one line per record to /tmp/cecore_mono_<pid>.txt (host side parses it):
 *   IMG <image-name>
 *   CLS <token> <Namespace>.<Name>
 *   FLD <offset> <S|-> <type-name> <field-name>      (S = static)
 * A leading "# ready" / "# error: …" line reports status.
 *
 * The agent runs on a detached thread that waits for the root domain to come up
 * (LD_PRELOAD's constructor fires before the runtime initializes), attaches
 * itself to the runtime, dumps once, and exits.
 *
 * Build target: libcecore_mono_agent.so
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
typedef MonoThread* (*fn_thread_attach)(MonoDomain*);
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

static struct {
    fn_get_root_domain     get_root_domain;
    fn_thread_attach       thread_attach;
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
} mono;

static FILE* g_out;

#define MONO_TABLE_TYPEDEF     0x02
#define MONO_TOKEN_TYPE_DEF    0x02000000u
#define FIELD_ATTRIBUTE_STATIC 0x0010

#define RESOLVE(field, sym)                                  \
    do {                                                     \
        mono.field = (void*)dlsym(RTLD_DEFAULT, sym);        \
        if (!mono.field) { missing = sym; }                  \
    } while (0)

/* Resolve the whole API; returns the name of the first missing symbol, or NULL. */
static const char* resolve_api(void) {
    const char* missing = NULL;
    RESOLVE(get_root_domain,     "mono_get_root_domain");
    RESOLVE(thread_attach,       "mono_thread_attach");
    RESOLVE(assembly_foreach,    "mono_assembly_foreach");
    RESOLVE(assembly_get_image,  "mono_assembly_get_image");
    RESOLVE(image_get_name,      "mono_image_get_name");
    RESOLVE(image_get_table_info,"mono_image_get_table_info");
    RESOLVE(table_info_get_rows, "mono_table_info_get_rows");
    RESOLVE(class_get,           "mono_class_get");
    RESOLVE(class_get_name,      "mono_class_get_name");
    RESOLVE(class_get_namespace, "mono_class_get_namespace");
    RESOLVE(class_get_fields,    "mono_class_get_fields");
    RESOLVE(field_get_name,      "mono_field_get_name");
    RESOLVE(field_get_offset,    "mono_field_get_offset");
    RESOLVE(field_get_type,      "mono_field_get_type");
    RESOLVE(type_get_name,       "mono_type_get_name");
    /* field_get_flags is optional (only used to tag statics). */
    mono.field_get_flags = (fn_field_get_flags)dlsym(RTLD_DEFAULT, "mono_field_get_flags");
    return missing;
}

static void dump_class(MonoClass* klass) {
    if (!klass) return;
    const char* ns   = mono.class_get_namespace ? mono.class_get_namespace(klass) : "";
    const char* name = mono.class_get_name ? mono.class_get_name(klass) : "?";
    fprintf(g_out, "CLS %s.%s\n", ns && *ns ? ns : "", name ? name : "?");

    void* iter = NULL;
    MonoClassField* f;
    while ((f = mono.class_get_fields(klass, &iter))) {
        const char* fname = mono.field_get_name(f);
        uint32_t off = mono.field_get_offset(f);
        int is_static = 0;
        if (mono.field_get_flags)
            is_static = (mono.field_get_flags(f) & FIELD_ATTRIBUTE_STATIC) != 0;
        char* tn = NULL;
        MonoType* ft = mono.field_get_type ? mono.field_get_type(f) : NULL;
        if (ft && mono.type_get_name) tn = mono.type_get_name(ft);
        fprintf(g_out, "FLD 0x%x %c %s %s\n", off, is_static ? 'S' : '-',
                tn ? tn : "?", fname ? fname : "?");
        if (tn) free(tn);   /* mono_type_get_name returns a g_malloc'd string */
    }
}

static void on_assembly(void* assembly, void* user_data) {
    (void)user_data;
    MonoImage* img = mono.assembly_get_image(assembly);
    if (!img) return;
    const char* iname = mono.image_get_name(img);
    fprintf(g_out, "IMG %s\n", iname ? iname : "?");

    MonoTableInfo* t = mono.image_get_table_info(img, MONO_TABLE_TYPEDEF);
    if (!t) return;
    int rows = mono.table_info_get_rows(t);
    /* Typedef tokens are 1-based; row 1 is the <Module> pseudo-class. */
    for (int i = 1; i <= rows; ++i) {
        MonoClass* klass = mono.class_get(img, MONO_TOKEN_TYPE_DEF | (uint32_t)i);
        dump_class(klass);
    }
}

static void* worker(void* arg) {
    (void)arg;
    char path[64];
    snprintf(path, sizeof(path), "/tmp/cecore_mono_%d.txt", (int)getpid());
    g_out = fopen(path, "we");
    if (!g_out) return NULL;

    const char* missing = resolve_api();
    if (missing) {
        fprintf(g_out, "# error: mono symbol not found: %s\n", missing);
        fflush(g_out); fclose(g_out); return NULL;
    }

    /* The LD_PRELOAD constructor fires before the runtime is up; wait for the
     * root domain (up to ~30s), then attach this thread so mono_* calls are legal. */
    MonoDomain* domain = NULL;
    for (int i = 0; i < 300; ++i) {
        domain = mono.get_root_domain();
        if (domain) break;
        usleep(100000);
    }
    if (!domain) {
        fprintf(g_out, "# error: root domain never came up\n");
        fflush(g_out); fclose(g_out); return NULL;
    }
    mono.thread_attach(domain);
    /* Give the app a moment to finish loading its own assemblies. */
    usleep(300000);

    fprintf(g_out, "# ready pid=%d\n", (int)getpid());
    mono.assembly_foreach(on_assembly, NULL);
    fprintf(g_out, "# done\n");
    fflush(g_out);
    fclose(g_out);
    return NULL;
}

__attribute__((constructor))
static void mono_agent_init(void) {
    pthread_t th;
    if (pthread_create(&th, NULL, worker, NULL) == 0)
        pthread_detach(th);
}
