/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * shield_misc.c - SELinux, getdents64, readlink hiding.
 * Ported from kpm_hide/hide_misc.c.
 * Uses configurable patterns from g_config.
 */

#include <compiler.h>
#include <hook.h>
#include <kputils.h>
#include <ksyms.h>
#include <ktypes.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>
#include <stdbool.h>

#include "shield_utils.h"

#define TAG "KPM_SHIELD/misc"

/* ========== hook status flags ========== */

static int fgetxattr_hooked = 0;
static int getsockopt_hooked = 0;
static int getdents_hooked = 0;
static int readlink_hooked = 0;

/* ========== SELinux: fgetxattr hook ========== */

static void fgetxattr_after(hook_fargs4_t *args, void *udata) {
    (void)udata;
    if (!is_app_process()) return;

    const char __user *name = (typeof(name))syscall_argn(args, 1);
    char buf[50];
    compat_strncpy_from_user(buf, name, sizeof(buf));

    if (strcmp(buf, "security.selinux") == 0) {
        const char __user *value = (typeof(value))syscall_argn(args, 2);
        char value_buf[128];
        compat_strncpy_from_user(value_buf, value, sizeof(value_buf));

        if (shield_pattern_match(value_buf, g_config.selinux_from, g_config.selinux_from_count)) {
            const char *replacement = g_config.selinux_to;
            if (replacement[0]) {
                compat_copy_to_user((void *__user)value, (const void *)replacement,
                                    strlen(replacement) + 1);
            }
        }
    }
}

/* ========== SELinux: getsockopt hook ========== */

static void getsockopt_after(hook_fargs5_t *args, void *udata) {
    (void)udata;
    if (!is_app_process()) return;

    const char __user *optval = (typeof(optval))syscall_argn(args, 3);
    char buf[50];
    compat_strncpy_from_user(buf, optval, sizeof(buf));

    if (shield_pattern_match(buf, g_config.selinux_from, g_config.selinux_from_count)) {
        const char *replacement = g_config.selinux_to;
        if (replacement[0]) {
            compat_copy_to_user((void *__user)optval, (const void *)replacement,
                                strlen(replacement) + 1);
        }
    }
}

/* ========== getdents64: hide directory entries ========== */

struct linux_dirent64 {
    u64 d_ino;
    s64 d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

static void getdents_after(hook_fargs3_t *args, void *udata) {
    (void)udata;
    if (!is_app_process()) return;

    void __user *dirp = (void __user *)syscall_argn(args, 1);
    long ret = args->ret;
    if (ret <= 0) return;

    void *kernel_buffer = kpm_vmalloc(ret);
    if (!kernel_buffer) return;

    if (kpm_arch_copy_from_user) {
        kpm_arch_copy_from_user(kernel_buffer, dirp, ret);
    } else {
        kpm_vfree(kernel_buffer);
        return;
    }

    void *filtered_buffer = kpm_vmalloc(ret);
    if (!filtered_buffer) {
        kpm_vfree(kernel_buffer);
        return;
    }

    long pos = 0;
    long new_pos = 0;

    while (pos < ret) {
        struct linux_dirent64 *current_dir =
            (struct linux_dirent64 *)((char *)kernel_buffer + pos);
        unsigned short reclen = current_dir->d_reclen;

        if (reclen == 0) break;

        char *name = current_dir->d_name;
        int should_filter = shield_pattern_match(name, g_config.dent_pat, g_config.dent_pat_count);

        if (!should_filter) {
            memcpy((char *)filtered_buffer + new_pos, current_dir, reclen);
            new_pos += reclen;
        }

        pos += reclen;
    }

    if (new_pos < ret) {
        compat_copy_to_user(dirp, filtered_buffer, new_pos);
        args->ret = new_pos;
    }

    kpm_vfree(filtered_buffer);
    kpm_vfree(kernel_buffer);
}

/* ========== readlinkat: hide paths ========== */

static void readlink_after(hook_fargs4_t *args, void *udata) {
    (void)udata;
    if (!is_app_process()) return;

    const char __user *path = (typeof(path))args->arg2;
    char buf[1024];
    compat_strncpy_from_user(buf, path, sizeof(buf));

    if (shield_pattern_match(buf, g_config.readlink_pat, g_config.readlink_pat_count)) {
        const char *replacement = "/dev/null";
        compat_copy_to_user((void *__user)path, (const void *)replacement,
                            strlen(replacement) + 1);
    }
}

/* ========== init / exit ========== */

int shield_misc_init(void) {
    hook_err_t err;

    err = fp_hook_syscalln(__NR_fgetxattr, 4, NULL, fgetxattr_after, NULL);
    if (!err) {
        fgetxattr_hooked = 1;
        pr_info(TAG ": fgetxattr hook installed\n");
    }

    err = fp_hook_syscalln(__NR_getsockopt, 5, NULL, getsockopt_after, NULL);
    if (!err) {
        getsockopt_hooked = 1;
        pr_info(TAG ": getsockopt hook installed\n");
    }

    err = fp_hook_syscalln(__NR_getdents64, 3, NULL, getdents_after, NULL);
    if (!err) {
        getdents_hooked = 1;
        pr_info(TAG ": getdents64 hook installed\n");
    }

    err = fp_hook_syscalln(__NR_readlinkat, 4, NULL, readlink_after, NULL);
    if (!err) {
        readlink_hooked = 1;
        pr_info(TAG ": readlinkat hook installed\n");
    }

    return 0;
}

void shield_misc_exit(void) {
    if (fgetxattr_hooked) {
        fp_unhook_syscalln(__NR_fgetxattr, 0, fgetxattr_after);
        pr_info(TAG ": fgetxattr hook removed\n");
    }
    if (getsockopt_hooked) {
        fp_unhook_syscalln(__NR_getsockopt, 0, getsockopt_after);
        pr_info(TAG ": getsockopt hook removed\n");
    }
    if (getdents_hooked) {
        fp_unhook_syscalln(__NR_getdents64, 0, getdents_after);
        pr_info(TAG ": getdents64 hook removed\n");
    }
    if (readlink_hooked) {
        fp_unhook_syscalln(__NR_readlinkat, 0, readlink_after);
        pr_info(TAG ": readlinkat hook removed\n");
    }
}
