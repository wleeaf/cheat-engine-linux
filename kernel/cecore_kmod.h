#pragma once

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <linux/types.h>
#include <sys/ioctl.h>
#endif

#define CECORE_KMOD_DEVICE "cecore"
#define CECORE_KMOD_PATH "/dev/cecore"
#define CECORE_KMOD_IOC_MAGIC 0xce

/*
 * Only PING and READ_PHYSICAL are served. The process, translation and
 * physical write requests are retired (the module answers -EOPNOTSUPP); their
 * numbers and structs stay reserved so old clients get a clear error. See
 * cecore_kmod.c for why.
 *
 * Every struct has the same layout for 32-bit and 64-bit callers. Pass
 * pointers as (__u64)(uintptr_t)ptr so a 32-bit pointer is zero-extended.
 */

/* Retired. */
struct cecore_kmod_mem_request {
    __u32 pid;
    __u32 flags;
    __u64 remote_address;
    __u64 user_buffer;
    __u64 size;
    __u64 bytes_transferred;
};

/* flags and reserved must be zero. */
struct cecore_kmod_phys_request {
    __u32 flags;
    __u32 reserved;
    __u64 physical_address;
    __u64 user_buffer;
    __u64 size;
    __u64 bytes_transferred;
};

/* Retired: read /proc/<pid>/pagemap instead. */
struct cecore_kmod_translate_request {
    __u32 pid;
    __u32 flags;
    __u64 virtual_address;
    __u64 physical_address;
    __u64 page_size;
    __u64 page_offset;
};

#define CECORE_KMOD_IOC_PING _IO(CECORE_KMOD_IOC_MAGIC, 0)
#define CECORE_KMOD_IOC_READ_PROCESS_VM \
    _IOWR(CECORE_KMOD_IOC_MAGIC, 1, struct cecore_kmod_mem_request)
#define CECORE_KMOD_IOC_WRITE_PROCESS_VM \
    _IOWR(CECORE_KMOD_IOC_MAGIC, 2, struct cecore_kmod_mem_request)
#define CECORE_KMOD_IOC_READ_PHYSICAL \
    _IOWR(CECORE_KMOD_IOC_MAGIC, 3, struct cecore_kmod_phys_request)
#define CECORE_KMOD_IOC_WRITE_PHYSICAL \
    _IOWR(CECORE_KMOD_IOC_MAGIC, 4, struct cecore_kmod_phys_request)
#define CECORE_KMOD_IOC_TRANSLATE_VA \
    _IOWR(CECORE_KMOD_IOC_MAGIC, 5, struct cecore_kmod_translate_request)
