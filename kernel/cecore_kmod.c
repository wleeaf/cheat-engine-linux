/*
 * Optional cecore kernel helper: read-only access to physical System RAM.
 *
 * The module does one thing user space cannot do on a kernel built with
 * CONFIG_STRICT_DEVMEM: read a physical RAM frame. Everything else goes
 * through interfaces that apply the kernel's own access checks:
 *
 * - Process memory: /proc/<pid>/mem. A module cannot call ptrace_may_access()
 *   (it is not exported), so a module that read or wrote another process
 *   would skip Yama ptrace_scope and every LSM. The process ioctls are retired
 *   and return -EOPNOTSUPP.
 * - Virtual to physical translation: /proc/<pid>/pagemap, which needs ptrace
 *   read access and CAP_SYS_ADMIN for frame numbers. TRANSLATE_VA is retired.
 * - Physical writes are refused. A frame number from pagemap is a snapshot:
 *   the page can be freed, migrated, merged by KSM or shared (the zero page,
 *   a page cache page of a library), so writing it can corrupt memory that
 *   belongs to someone else. Write through /proc/<pid>/mem instead, which
 *   breaks copy-on-write correctly.
 *
 * Physical reads need CAP_SYS_ADMIN and CAP_SYS_RAWIO, are refused under
 * kernel lockdown (like /dev/mem), and only touch online System RAM pages
 * through the kernel mapping. MMIO, firmware areas and holes return -EINVAL,
 * and a page missing from the kernel mapping returns -EIO instead of oopsing.
 */
#include "cecore_kmod.h"

#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/memory_hotplug.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/page-flags.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

static int cecore_check_physical_access(void)
{
    if (!capable(CAP_SYS_ADMIN) || !capable(CAP_SYS_RAWIO))
        return -EPERM;
    /* Same rule as /dev/mem: no raw memory access under lockdown. */
    return security_locked_down(LOCKDOWN_DEV_MEM);
}

/* True when [start, start + size) fits below max + 1, without overflow. */
static bool cecore_range_fits(u64 start, u64 size, u64 max)
{
    if (size == 0)
        return start <= max;
    return start <= max && size - 1 <= max - start;
}

/* Returns the online System RAM page holding phys, or NULL. */
static struct page *cecore_ram_page(u64 phys)
{
    u64 pfn = phys >> PAGE_SHIFT;
    struct page *page;

    if (pfn > ULONG_MAX)
        return NULL;
    if (region_intersects((resource_size_t)(phys & ~(u64)(PAGE_SIZE - 1)), PAGE_SIZE,
                          IORESOURCE_SYSTEM_RAM, IORES_DESC_NONE) != REGION_INTERSECTS)
        return NULL;
    page = pfn_to_online_page((unsigned long)pfn);
    if (!page)
        return NULL;
    /* /proc/kcore skips these too: poisoned frames and frames given back to a hypervisor. */
    if (PageHWPoison(page) || PageOffline(page))
        return NULL;
    return page;
}

static int cecore_read_physical(struct cecore_kmod_phys_request *req)
{
    char *bounce;
    u64 done = 0;
    int ret = 0;

    req->bytes_transferred = 0;
    if (req->flags || req->reserved || !req->user_buffer)
        return -EINVAL;
    if (req->size == 0)
        return 0;
    /*
     * Both ranges must be addressable by the caller. This bounds size by
     * SIZE_MAX on 32-bit kernels and keeps a 32-bit caller's buffer below
     * 4 GiB on a 64-bit kernel.
     */
    if (!cecore_range_fits(req->user_buffer, req->size,
                           in_compat_syscall() ? (u64)U32_MAX : (u64)ULONG_MAX) ||
        !cecore_range_fits(req->physical_address, req->size, (u64)PHYS_ADDR_MAX))
        return -EINVAL;

    bounce = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!bounce)
        return -ENOMEM;

    while (done < req->size) {
        u64 phys = req->physical_address + done;
        size_t page_offset = (size_t)(phys & (PAGE_SIZE - 1));
        size_t chunk = PAGE_SIZE - page_offset;
        void __user *user = u64_to_user_ptr(req->user_buffer + done);
        struct page *page;
        void *mapped;
        long failed;

        if (chunk > req->size - done)
            chunk = (size_t)(req->size - done);

        if (fatal_signal_pending(current)) {
            ret = -EINTR;
            break;
        }
        cond_resched();

        page = cecore_ram_page(phys);
        if (!page) {
            ret = -EINVAL;
            break;
        }

        /*
         * The frame may be freed or reused while we copy; that only changes
         * which bytes we see. The nofault copy turns a frame that is missing
         * from the kernel mapping (secretmem, debug_pagealloc) into -EIO.
         */
        mapped = kmap_local_page(page);
        failed = copy_from_kernel_nofault(bounce, (char *)mapped + page_offset, chunk);
        kunmap_local(mapped);
        if (failed) {
            ret = -EIO;
            break;
        }
        if (copy_to_user(user, bounce, chunk)) {
            ret = -EFAULT;
            break;
        }
        done += chunk;
    }

    kfree(bounce);
    req->bytes_transferred = done;
    return done ? 0 : ret;
}

static long cecore_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    void __user *argp = (void __user *)arg;
    struct cecore_kmod_phys_request phys_req;
    long result;

    (void)file;

    switch (cmd) {
    case CECORE_KMOD_IOC_PING:
        return cecore_check_physical_access();

    case CECORE_KMOD_IOC_READ_PHYSICAL:
        result = cecore_check_physical_access();
        if (result)
            return result;
        if (copy_from_user(&phys_req, argp, sizeof(phys_req)))
            return -EFAULT;
        result = cecore_read_physical(&phys_req);
        if (copy_to_user(argp, &phys_req, sizeof(phys_req)))
            return -EFAULT;
        return result;

    case CECORE_KMOD_IOC_READ_PROCESS_VM:
    case CECORE_KMOD_IOC_WRITE_PROCESS_VM:
    case CECORE_KMOD_IOC_WRITE_PHYSICAL:
    case CECORE_KMOD_IOC_TRANSLATE_VA:
        /* Retired; see the comment at the top of this file. */
        return -EOPNOTSUPP;

    default:
        return -ENOTTY;
    }
}

static const struct file_operations cecore_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = cecore_ioctl,
    /* The request structs have the same layout for 32-bit callers. */
    .compat_ioctl = compat_ptr_ioctl,
};

static struct miscdevice cecore_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = CECORE_KMOD_DEVICE,
    .fops = &cecore_fops,
    .mode = 0600,
};

static int __init cecore_kmod_init(void)
{
    return misc_register(&cecore_miscdev);
}

static void __exit cecore_kmod_exit(void)
{
    misc_deregister(&cecore_miscdev);
}

module_init(cecore_kmod_init);
module_exit(cecore_kmod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cecore");
MODULE_DESCRIPTION("Cheat Engine Linux helper: read-only physical RAM access");
