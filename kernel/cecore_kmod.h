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

struct cecore_kmod_mem_request {
    __u32 pid;
    __u32 flags;
    __u64 remote_address;
    __u64 user_buffer;
    __u64 size;
    __u64 bytes_transferred;
};

struct cecore_kmod_phys_request {
    __u32 flags;
    __u32 reserved;
    __u64 physical_address;
    __u64 user_buffer;
    __u64 size;
    __u64 bytes_transferred;
};

struct cecore_kmod_translate_request {
    __u32 pid;
    __u32 flags;
    __u64 virtual_address;
    __u64 physical_address;
    __u64 page_size;
    __u64 page_offset;
 };

/* Process-hiding request — adds or removes a PID from the kernel's hide
 * list. While a PID is on the list, /proc/<pid>/ entries are filtered out
 * of directory iteration so user-space tools that walk /proc (ps, top,
 * games doing string scans of their environment) don't see that pid.
 *
 * Scope: this is for hiding cecore itself from single-player anti-tamper
 * checks. It does NOT defeat dedicated anti-cheat kernel modules
 * (EAC/BattlEye/Vanguard etc) which run their own ring-0 detection.
 */
struct cecore_kmod_hide_request {
    __u32 pid;
    __u32 reserved;
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
#define CECORE_KMOD_IOC_HIDE_PID \
    _IOW(CECORE_KMOD_IOC_MAGIC, 6, struct cecore_kmod_hide_request)
#define CECORE_KMOD_IOC_UNHIDE_PID \
    _IOW(CECORE_KMOD_IOC_MAGIC, 7, struct cecore_kmod_hide_request)
