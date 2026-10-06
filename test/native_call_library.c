#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdatomic.h>

__attribute__((constructor)) static void loaded(void) {
    _Atomic unsigned* count = dlsym(RTLD_DEFAULT, "ce_call_loaded");
    if (count) atomic_fetch_add(count, 1);
}
