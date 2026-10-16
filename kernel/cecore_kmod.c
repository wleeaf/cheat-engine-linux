#include "cecore_kmod.h"

#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
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

static long cecore_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct cecore_kmod_mem_request req;
    struct cecore_kmod_phys_request phys_req;
    struct cecore_kmod_translate_request translate_req;
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
    misc_deregister(&cecore_miscdev);
}

module_init(cecore_kmod_init);
module_exit(cecore_kmod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cecore");
MODULE_DESCRIPTION("Cheat Engine Linux privileged process-memory helper");
