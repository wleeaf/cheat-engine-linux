#include "cecore_kmod.h"

#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/pid.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#define CECORE_KMOD_CHUNK_SIZE (64 * 1024)

static int cecore_check_privilege(void)
{
    return capable(CAP_SYS_ADMIN) ? 0 : -EPERM;
}

static ssize_t cecore_access_process_vm(struct cecore_kmod_mem_request *req, int write)
{
    struct task_struct *task;
    void *buffer;
    size_t done = 0;
    int ret = 0;

    if (!req->pid || !req->remote_address || !req->user_buffer)
        return -EINVAL;
    if (req->size == 0)
        return 0;
    /* Reject wrapping ranges (remote_address/user_buffer/size are attacker-controlled). */
    if (req->remote_address + req->size < req->remote_address ||
        req->user_buffer + req->size < req->user_buffer)
        return -EINVAL;

    buffer = kmalloc(CECORE_KMOD_CHUNK_SIZE, GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;

    rcu_read_lock();
    task = get_pid_task(find_vpid(req->pid), PIDTYPE_PID);
    rcu_read_unlock();
    if (!task) {
        kfree(buffer);
        return -ESRCH;
    }

    while (done < req->size) {
        size_t chunk = min_t(size_t, CECORE_KMOD_CHUNK_SIZE, req->size - done);
        unsigned long remote = (unsigned long)(req->remote_address + done);
        void __user *user = (void __user *)(uintptr_t)(req->user_buffer + done);
        int copied;

        if (write) {
            if (copy_from_user(buffer, user, chunk)) {
                ret = -EFAULT;
                break;
            }
            copied = access_process_vm(task, remote, buffer, chunk, FOLL_WRITE);
        } else {
            copied = access_process_vm(task, remote, buffer, chunk, 0);
            if (copied > 0 && copy_to_user(user, buffer, copied)) {
                ret = -EFAULT;
                break;
            }
        }

        if (copied <= 0) {
            ret = copied < 0 ? copied : -EFAULT;
            break;
        }

        done += copied;
        if ((size_t)copied < chunk)
            break;
    }

    put_task_struct(task);
    kfree(buffer);
    req->bytes_transferred = done;
    return done ? (ssize_t)done : ret;
}

static ssize_t cecore_access_physical(struct cecore_kmod_phys_request *req, int write)
{
    size_t done = 0;
    int ret = 0;

    if (!req->user_buffer)
        return -EINVAL;
    if (req->size == 0)
        return 0;
    /* Reject wrapping ranges (physical_address/user_buffer/size are attacker-controlled). */
    if (req->physical_address + req->size < req->physical_address ||
        req->user_buffer + req->size < req->user_buffer)
        return -EINVAL;

    while (done < req->size) {
        phys_addr_t phys = (phys_addr_t)(req->physical_address + done);
        size_t page_offset = offset_in_page(phys);
        size_t chunk = min_t(size_t, PAGE_SIZE - page_offset, req->size - done);
        void __iomem *mapped;
        void __user *user = (void __user *)(uintptr_t)(req->user_buffer + done);

        /*
         * Physical RAM access is intentionally permitted (a Cheat-Engine/DBVM
         * capability). ioremap() of RAM is a powerful and dangerous primitive
         * — it can corrupt kernel structures or leak secrets — so the device
         * node stays root/CAP_SYS_ADMIN-gated (cecore_check_privilege) and the
         * [physical_address, +size) range is wrap-checked above.
         * TODO(security): for RAM specifically, prefer memremap()/kmap of a
         * pfn_valid() struct page over ioremap, and honor kernel lockdown
         * (security_locked_down(LOCKDOWN_DEV_MEM)) when configured.
         */
        mapped = ioremap(phys & PAGE_MASK, PAGE_SIZE);
        if (!mapped) {
            ret = -ENOMEM;
            break;
        }

        if (write) {
            void *buffer = memdup_user(user, chunk);
            if (IS_ERR(buffer)) {
                ret = PTR_ERR(buffer);
                iounmap(mapped);
                break;
            }
            memcpy_toio((char __iomem *)mapped + page_offset, buffer, chunk);
            kfree(buffer);
        } else {
            void *buffer = kmalloc(chunk, GFP_KERNEL);
            if (!buffer) {
                ret = -ENOMEM;
                iounmap(mapped);
                break;
            }
            memcpy_fromio(buffer, (char __iomem *)mapped + page_offset, chunk);
            if (copy_to_user(user, buffer, chunk))
                ret = -EFAULT;
            kfree(buffer);
            if (ret) {
                iounmap(mapped);
                break;
            }
        }

        iounmap(mapped);
        done += chunk;
    }

    req->bytes_transferred = done;
    return done ? (ssize_t)done : ret;
}

static int cecore_translate_va(struct cecore_kmod_translate_request *req)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct page *page = NULL;
    unsigned long address;
    long pinned;
    int ret = 0;

    if (!req->pid || !req->virtual_address)
        return -EINVAL;

    rcu_read_lock();
    task = get_pid_task(find_vpid(req->pid), PIDTYPE_PID);
    rcu_read_unlock();
    if (!task)
        return -ESRCH;

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return -EINVAL;

    address = (unsigned long)(req->virtual_address & PAGE_MASK);
    mmap_read_lock(mm);
    pinned = get_user_pages_remote(mm, address, 1, FOLL_GET, &page, NULL);
    mmap_read_unlock(mm);
    mmput(mm);

    if (pinned != 1 || !page) {
        ret = pinned < 0 ? pinned : -EFAULT;
        return ret;
    }

    req->page_size = PAGE_SIZE; /* NOTE: always reports base page size; huge-page mappings are not detected. */
    req->page_offset = offset_in_page(req->virtual_address);
    req->physical_address = page_to_phys(page) + req->page_offset;
    put_page(page);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────
 * Process hiding — filter /proc/<pid> directory entries
 *
 * Use case: hide cecore itself from single-player anti-tamper string
 * scans. This is NOT a defence against dedicated anti-cheat kernel
 * modules (EAC/BattlEye/Vanguard etc.) which run their own ring-0
 * detection and will identify the hook itself. Documented as such in
 * the public header.
 *
 * Mechanism: at the first hide request we resolve /proc's inode,
 * duplicate its file_operations, swap iterate_shared for our wrapper,
 * and point inode->i_fop at the duplicate. The wrapper uses the
 * container_of dir_context trick to filter PID-named entries.
 * On module unload we restore the original.
 * ─────────────────────────────────────────────────────────────────*/

#define CECORE_HIDE_LIST_MAX 32

static DEFINE_SPINLOCK(cecore_hide_lock);
static pid_t cecore_hidden_pids[CECORE_HIDE_LIST_MAX];
static int   cecore_hidden_count;

static struct file_operations cecore_proc_fops;
static const struct file_operations *cecore_proc_fops_orig;
static int (*cecore_proc_iterate_orig)(struct file *, struct dir_context *);
static struct inode *cecore_proc_inode;
static struct dentry *cecore_proc_dentry;

static bool cecore_pid_is_hidden(pid_t pid)
{
    bool hidden = false;
    unsigned long flags;
    int i;
    spin_lock_irqsave(&cecore_hide_lock, flags);
    for (i = 0; i < cecore_hidden_count; ++i) {
        if (cecore_hidden_pids[i] == pid) { hidden = true; break; }
    }
    spin_unlock_irqrestore(&cecore_hide_lock, flags);
    return hidden;
}

static int cecore_pid_hide_add(pid_t pid)
{
    unsigned long flags;
    int i, rc = 0;
    if (pid <= 0) return -EINVAL;
    spin_lock_irqsave(&cecore_hide_lock, flags);
    for (i = 0; i < cecore_hidden_count; ++i) {
        if (cecore_hidden_pids[i] == pid) { rc = 0; goto out; }
    }
    if (cecore_hidden_count >= CECORE_HIDE_LIST_MAX) { rc = -ENOSPC; goto out; }
    cecore_hidden_pids[cecore_hidden_count++] = pid;
out:
    spin_unlock_irqrestore(&cecore_hide_lock, flags);
    return rc;
}

static int cecore_pid_hide_remove(pid_t pid)
{
    unsigned long flags;
    int i;
    spin_lock_irqsave(&cecore_hide_lock, flags);
    for (i = 0; i < cecore_hidden_count; ++i) {
        if (cecore_hidden_pids[i] == pid) {
            cecore_hidden_pids[i] = cecore_hidden_pids[--cecore_hidden_count];
            spin_unlock_irqrestore(&cecore_hide_lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&cecore_hide_lock, flags);
    return -ENOENT;
}

struct cecore_dir_ctx {
    struct dir_context ctx;
    struct dir_context *orig;
};

static bool cecore_filter_actor(struct dir_context *ctx, const char *name,
                                int namelen, loff_t offset, u64 ino,
                                unsigned int d_type)
{
    struct cecore_dir_ctx *h = container_of(ctx, struct cecore_dir_ctx, ctx);

    /* Skip the entry when name parses as a hidden PID. */
    if (namelen > 0 && namelen < 12) {
        char buf[12] = {0};
        long pid;
        memcpy(buf, name, namelen);
        if (!kstrtol(buf, 10, &pid) && pid > 0 && cecore_pid_is_hidden((pid_t)pid))
            return true; /* signal continue, skipping this entry */
    }
    return h->orig->actor(h->orig, name, namelen, offset, ino, d_type);
}

static int cecore_hooked_iterate_shared(struct file *file, struct dir_context *ctx)
{
    struct cecore_dir_ctx h = {
        .ctx  = { .actor = cecore_filter_actor, .pos = ctx->pos },
        .orig = ctx,
    };
    int rc;

    if (!cecore_proc_iterate_orig)
        return -ENOSYS;

    rc = cecore_proc_iterate_orig(file, &h.ctx);
    ctx->pos = h.ctx.pos;
    return rc;
}

static int cecore_install_proc_hook(void)
{
    struct path p;
    int rc;

    if (cecore_proc_inode) return 0;  /* already installed */

    rc = kern_path("/proc", LOOKUP_FOLLOW, &p);
    if (rc) return rc;

    cecore_proc_inode = d_inode(p.dentry);
    if (!cecore_proc_inode) {
        path_put(&p);
        return -ENOENT;
    }
    /* Hold an extra ref on the dentry so the inode pointer stays valid;
     * released in cecore_remove_proc_hook(). */
    dget(p.dentry);
    cecore_proc_dentry = p.dentry;

    cecore_proc_fops_orig    = cecore_proc_inode->i_fop;
    cecore_proc_fops         = *cecore_proc_fops_orig;
    cecore_proc_iterate_orig = cecore_proc_fops.iterate_shared;
    cecore_proc_fops.iterate_shared = cecore_hooked_iterate_shared;
    /*
     * Pin this module whenever the hooked /proc directory is opened: the VFS
     * calls try_module_get(f_op->owner) on open, so an in-flight `ls /proc`
     * keeps the module loaded and blocks rmmod while the hook can still run,
     * closing the common use-after-free-on-unload window.
     */
    cecore_proc_fops.owner = THIS_MODULE;
    cecore_proc_inode->i_fop = &cecore_proc_fops;

    path_put(&p);
    return 0;
}

static void cecore_remove_proc_hook(void)
{
    if (!cecore_proc_inode) return;
    cecore_proc_inode->i_fop = cecore_proc_fops_orig;
    /*
     * Best-effort grace period for any iterator that already loaded the hooked
     * i_fop pointer before we restored it. Combined with the THIS_MODULE owner
     * pin taken at open time (see install), this closes the practical unload
     * race for the common case.
     * TODO(security): the i_fop pointer-swap /proc-hiding technique is
     * fundamentally racy against concurrent openers on a shared live inode and
     * should be replaced with a non-hijacking mechanism rather than mitigated.
     */
    synchronize_rcu();
    if (cecore_proc_dentry) {
        dput(cecore_proc_dentry);
        cecore_proc_dentry = NULL;
    }
    cecore_proc_inode = NULL;
    cecore_proc_fops_orig = NULL;
    cecore_proc_iterate_orig = NULL;
}

static long cecore_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct cecore_kmod_mem_request req;
    struct cecore_kmod_phys_request phys_req;
    struct cecore_kmod_translate_request translate_req;
    struct cecore_kmod_hide_request hide_req;
    ssize_t result;

    (void)file;

    if (cmd == CECORE_KMOD_IOC_PING)
        return cecore_check_privilege();

    if (cmd == CECORE_KMOD_IOC_READ_PHYSICAL ||
        cmd == CECORE_KMOD_IOC_WRITE_PHYSICAL) {
        result = cecore_check_privilege();
        if (result)
            return result;
        if (copy_from_user(&phys_req, (void __user *)arg, sizeof(phys_req)))
            return -EFAULT;
        result = cecore_access_physical(&phys_req, cmd == CECORE_KMOD_IOC_WRITE_PHYSICAL);
        if (copy_to_user((void __user *)arg, &phys_req, sizeof(phys_req)))
            return -EFAULT;
        return result < 0 ? result : 0;
    }

    if (cmd == CECORE_KMOD_IOC_TRANSLATE_VA) {
        result = cecore_check_privilege();
        if (result)
            return result;
        if (copy_from_user(&translate_req, (void __user *)arg, sizeof(translate_req)))
            return -EFAULT;
        result = cecore_translate_va(&translate_req);
        if (copy_to_user((void __user *)arg, &translate_req, sizeof(translate_req)))
            return -EFAULT;
        return result;
    }

    if (cmd == CECORE_KMOD_IOC_HIDE_PID ||
        cmd == CECORE_KMOD_IOC_UNHIDE_PID) {
        result = cecore_check_privilege();
        if (result)
            return result;
        if (copy_from_user(&hide_req, (void __user *)arg, sizeof(hide_req)))
            return -EFAULT;
        if (cmd == CECORE_KMOD_IOC_HIDE_PID) {
            result = cecore_install_proc_hook();
            if (result)
                return result;
            return cecore_pid_hide_add((pid_t)hide_req.pid);
        }
        return cecore_pid_hide_remove((pid_t)hide_req.pid);
    }

    if (cmd != CECORE_KMOD_IOC_READ_PROCESS_VM &&
        cmd != CECORE_KMOD_IOC_WRITE_PROCESS_VM)
        return -ENOTTY;

    result = cecore_check_privilege();
    if (result)
        return result;

    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;

    result = cecore_access_process_vm(&req, cmd == CECORE_KMOD_IOC_WRITE_PROCESS_VM);
    if (copy_to_user((void __user *)arg, &req, sizeof(req)))
        return -EFAULT;
    return result < 0 ? result : 0;
}

static const struct file_operations cecore_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = cecore_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = cecore_ioctl,
#endif
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
    cecore_remove_proc_hook();
    misc_deregister(&cecore_miscdev);
}

module_init(cecore_kmod_init);
module_exit(cecore_kmod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cecore");
MODULE_DESCRIPTION("Cheat Engine Linux privileged process-memory helper");
