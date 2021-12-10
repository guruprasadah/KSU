// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

/* Hello. If this is enabled in your kernel for some reason, whoever is
 * distributing your kernel to you is a complete moron, and you shouldn't
 * use their kernel anymore. But it's not my fault! People: don't enable
 * this driver! (Note that the existence of this file does not imply the
 * driver is actually in use. Look in your .config to see whether this is
 * enabled.) -Jason
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include<linux/slab.h>
#include <linux/ioctl.h>

int status = 0;

dev_t dev = 0;
static struct class *dev_class;
static struct cdev ksu_cdev;

#define KSU_ALLOW _IO('ksu','allow')
#define KSU_DENY _IO('ksu','denied')

static int      ksu_open(struct inode *inode, struct file *file);
static int      ksu_release(struct inode *inode, struct file *file);
static ssize_t  ksu_read(struct file *filp, char __user *buf, size_t len,loff_t * off);
static ssize_t  ksu_write(struct file *filp, const char *buf, size_t len, loff_t * off);
static long     ksu_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

static struct file_operations fops =
{
        .owner          = THIS_MODULE,
        .read           = ksu_read,
        .write          = ksu_write,
        .open           = ksu_open,
        .unlocked_ioctl = ksu_ioctl,
        .release        = ksu_release,
};

static int ksu_open(struct inode *inode, struct file *file)
{
        pr_info("Device File Opened...!!!\n");
        return 0;
}

static int ksu_release(struct inode *inode, struct file *file)
{
        pr_info("Device File Closed...!!!\n");
        return 0;
}

static ssize_t ksu_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
        pr_info("Read Function\n");
        return 0;
}

static ssize_t ksu_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
        pr_info("Write function\n");
        return len;
}

static long ksu_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
         switch(cmd) {
                case KSU_ALLOW:
                        status = 1;
                        break;
                case KSU_DENY:
                        status = -1;
                        break;
                default:
                 // Cue a message that  noone will will look at which I typed out manually
                        pr_info("Never gonna give you up!!!\n Never gonna let you down! \n Never gonna run around and desert you \n Never gonna make you cry \n Never gonna say goodbye \n Never gonna tell a lie and hurt you");
                        break;
        }
        return 0;
}

static int cr_dev() {
    if((alloc_chrdev_region(&dev, 0, 1, "0.69")) <0){
                pr_err("Cannot allocate major number\n");
                return -1;
        }
        pr_info("Major = %d Minor = %d \n",MAJOR(dev), MINOR(dev));

        /*Creating cdev structure*/
        cdev_init(&etx_cdev,&fops);

        /*Adding character device to the system*/
        if((cdev_add(&etx_cdev,dev,1)) < 0){
            pr_err("Cannot add the device to the system\n");
            goto r_class;
        }

        /*Creating struct class*/
        if((dev_class = class_create(THIS_MODULE,"ksuClass")) == NULL){
            pr_err("Cannot create the struct class\n");
            goto r_class;
        }

        /*Creating device*/
        if((device_create(dev_class,NULL,dev,NULL,"ksuDev")) == NULL){
            pr_err("Cannot create the Device 1\n");
            goto r_device;
        }
        pr_info("Device Driver Insert...Done!!!\n");
        return 0;

r_device:
        class_destroy(dev_class);
r_class:
        unregister_chrdev_region(dev,1);
        return -1;
}

static int chk(uid_t uid) {

    char ∗argv[] = { "/data/adb/ksu", "chk", uid, NULL };
    static char ∗envp[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

    return call_usermodehelper( argv[0], argv, envp, UMH_WAIT_PROC );

}

static int is_allowed(uid_t uid) {
    status = 0;
    chk(uid);
    while (status != 0) {
        // Not gonna waste my time again
    }

    if(status = 1) {
        return true;
    } else if (status = -1) {
        return false;
    } else {
        return false;
    }
}

static bool is_su(const char __user *filename)
{
	static const char su_path[] = "/system/bin/su";
	char ufn[sizeof(su_path)];

	return likely(!copy_from_user(ufn, filename, sizeof(ufn))) &&
	       unlikely(!memcmp(ufn, su_path, sizeof(ufn)));
}

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	/* To avoid having to mmap a page in userspace, just write below the stack pointer. */
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
	static const char sh_path[] = "/system/bin/sh";

	return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static long(*old_newfstatat)(int dfd, const char __user *filename,
			     struct stat *statbuf, int flag);
static long new_newfstatat(int dfd, const char __user *filename,
			   struct stat __user *statbuf, int flag)
{
	if (!is_su(filename))
	{
	return old_newfstatat(dfd, filename, statbuf, flag);
	}
	if (is_allowed(current_uid().val) {
	return old_newfstatat(dfd, sh_user_path(), statbuf, flag);
	}
	else {
	return old_newfstatat(dfd, NULL, statbuf, flag);
	}
}

static long(*old_faccessat)(int dfd, const char __user *filename, int mode);
static long new_faccessat(int dfd, const char __user *filename, int mode)
{
	if (!is_su(filename))
		return old_faccessat(dfd, filename, mode);
	if (is_allowed(current_uid().val) {
	return old_faccessat(dfd, sh_user_path(), statbuf, flag);
	}
	else {
	return old_faccessat(dfd, filename, statbuf, flag);
	}
}

extern int selinux_enforcing;
static long (*old_execve)(const char __user *filename,
			  const char __user *const __user *argv,
			  const char __user *const __user *envp);
static long new_execve(const char __user *filename,
		       const char __user *const __user *argv,
		       const char __user *const __user *envp)
{
	static const char now_root[] = "You are now root.\n";
	struct cred *cred;

	if (!is_su(filename))
		return old_execve(filename, argv, envp);

	if (!old_execve(filename, argv, envp))
		return 0;

	/* It might be enough to just change the security ctx of the
	 * current task, but that requires slightly more thought than
	 * just axing the whole thing here.
	 */
	selinux_enforcing = 0;

	/* Rather than the usual commit_creds(prepare_kernel_cred(NULL)) idiom,
	 * we manually zero out the fields in our existing one, so that we
	 * don't have to futz with the task's key ring for disk access.
	 */
	cred = (struct cred *)__task_cred(current);
    if (is_allowed(cred->uid)) {
	memset(&cred->uid, 0, sizeof(cred->uid));
	memset(&cred->gid, 0, sizeof(cred->gid));
	memset(&cred->suid, 0, sizeof(cred->suid));
	memset(&cred->euid, 0, sizeof(cred->euid));
	memset(&cred->egid, 0, sizeof(cred->egid));
	memset(&cred->fsuid, 0, sizeof(cred->fsuid));
	memset(&cred->fsgid, 0, sizeof(cred->fsgid));
	memset(&cred->cap_inheritable, 0xff, sizeof(cred->cap_inheritable));
	memset(&cred->cap_permitted, 0xff, sizeof(cred->cap_permitted));
	memset(&cred->cap_effective, 0xff, sizeof(cred->cap_effective));
	memset(&cred->cap_bset, 0xff, sizeof(cred->cap_bset));
	memset(&cred->cap_ambient, 0xff, sizeof(cred->cap_ambient));
    }
    else {
        // Never gonna give you up, keep trying.
        now_root[] = "Superuser perms denied hahahaha"
    }

	sys_write(2, userspace_stack_buffer(now_root, sizeof(now_root)),
		  sizeof(now_root) - 1);
    if (is_allowed(cred->uid))
    {
       return old_execve(sh_user_path(), argv, envp);
    }
    else {
        return old_execve(filename, argv, envp);
    }

}

extern const unsigned long sys_call_table[];
static void read_syscall(void **ptr, unsigned int syscall)
{
	*ptr = READ_ONCE(*((void **)sys_call_table + syscall));
}
static void replace_syscall(unsigned int syscall, void *ptr)
{
	WRITE_ONCE(*((void **)sys_call_table + syscall), ptr);
}
#define read_and_replace_syscall(name) do { \
	read_syscall((void **)&old_ ## name, __NR_ ## name); \
	replace_syscall(__NR_ ## name, &new_ ## name); \
} while (0)

static int superuser_init(void)
{
	pr_err("Sort of secure implementation of su, not trusted (yet)");


	read_and_replace_syscall(newfstatat);
	read_and_replace_syscall(faccessat);
	read_and_replace_syscall(execve);

	return 0;
}

module_init(superuser_init);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Kernel-assisted superuser for Android");
MODULE_AUTHOR("Jason A. Donenfeld <Jason@zx2c4.com>");
