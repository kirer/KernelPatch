/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * hide_misc.c - Miscellaneous APatch environment hiding:
 *   - SELinux context: fgetxattr / getsockopt hooks
 *   - Directory entries: getdents64 hook (hide debug_ramdisk)
 *   - Readlink: readlinkat hook (hide zygisk paths)
 *
 * Ported from xiaojia-hide/src/hide_proc.c.
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

#include "kpm_utils.h"

#define TAG "KPM_HIDE/misc"

/* ========== hook status flags ========== */

static int fgetxattr_hooked = 0;
static int getsockopt_hooked = 0;
static int getdents_hooked = 0;
static int readlink_hooked = 0;

/* ========== SELinux: fgetxattr hook ========== */

static void fgetxattr_after(hook_fargs4_t *args, void *udata) {
    if (!is_app_process()) return;

    const char __user *name = (typeof(name))syscall_argn(args, 1);
    char buf[50];
    compat_strncpy_from_user(buf, name, sizeof(buf));

    if (strcmp(buf, "security.selinux") == 0) {
        const char __user *value = (typeof(value))syscall_argn(args, 2);
        char value_buf[128];
        compat_strncpy_from_user(value_buf, value, sizeof(value_buf));
        if (strcmp(value_buf, "u:r:magisk:s0") == 0 ||
            strcmp(value_buf, "u:r:su:s0") == 0) {
            const char *replacement = "u:r:surfaceflinger:s0";
            compat_copy_to_user((void *__user)value, (const void *)replacement,
                                strlen(replacement) + 1);
        }
    }
}

/* ========== SELinux: getsockopt hook ========== */

static void getsockopt_after(hook_fargs5_t *args, void *udata) {
    if (!is_app_process()) return;

    const char __user *optval = (typeof(optval))syscall_argn(args, 3);
    char buf[50];
    compat_strncpy_from_user(buf, optval, sizeof(buf));

    if (strcmp(buf, "u:r:magisk:s0") == 0 || strcmp(buf, "u:r:su:s0") == 0) {
        const char *replacement = "u:r:surfaceflinger:s0";
        compat_copy_to_user((void *__user)optval, (const void *)replacement,
                            strlen(replacement) + 1);
    }
}

/* ========== getdents64: hide debug_ramdisk ========== */

struct linux_dirent64 {
    u64 d_ino;
    s64 d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

static void getdents_after(hook_fargs3_t *args, void *udata) {
    if (!is_app_process()) return;

    const char *filter_names[] = {
        "debug_ramdisk",
        NULL
    };

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
        int should_filter = 0;
        for (int i = 0; filter_names[i] != NULL; i++) {
            if (strcmp(name, filter_names[i]) == 0) {
                should_filter = 1;
                break;
            }
        }

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

/* ========== readlinkat: hide zygisk paths ========== */

static void readlink_after(hook_fargs4_t *args, void *udata) {
    if (!is_app_process()) return;

    const char __user *path = (typeof(path))args->arg2;
    char buf[1024];
    compat_strncpy_from_user(buf, path, sizeof(buf));

    if (strstr(buf, "zygisk_gadget") || strstr(buf, "zygisk_lsposed") ||
        strstr(buf, "memfd:wwb")) {
        const char *replacement = "/dev/null";
        compat_copy_to_user((void *__user)path, (const void *)replacement,
                            strlen(replacement) + 1);
    }
}

/* ========== init / exit ========== */

int hide_misc_init(void) {
    hook_err_t err;

    /* SELinux fgetxattr */
    err = fp_hook_syscalln(__NR_fgetxattr, 4, NULL, fgetxattr_after, NULL);
    if (!err) {
        fgetxattr_hooked = 1;
        pr_info(TAG ": fgetxattr hook installed\n");
    }

    /* SELinux getsockopt */
    err = fp_hook_syscalln(__NR_getsockopt, 5, NULL, getsockopt_after, NULL);
    if (!err) {
        getsockopt_hooked = 1;
        pr_info(TAG ": getsockopt hook installed\n");
    }

    /* getdents64 */
    err = fp_hook_syscalln(__NR_getdents64, 3, NULL, getdents_after, NULL);
    if (!err) {
        getdents_hooked = 1;
        pr_info(TAG ": getdents64 hook installed\n");
    }

    /* readlinkat */
    err = fp_hook_syscalln(__NR_readlinkat, 4, NULL, readlink_after, NULL);
    if (!err) {
        readlink_hooked = 1;
        pr_info(TAG ": readlinkat hook installed\n");
    }

    return 0;
}

void hide_misc_exit(void) {
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
