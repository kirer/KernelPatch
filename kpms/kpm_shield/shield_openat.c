/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * shield_openat.c - Block frida file probes via openat, faccessat, fstatat.
 * Ported from kpm_frida/openat_hide.c.
 * Uses configurable block_paths from g_config.
 */

#include "shield_openat.h"

#include <compiler.h>
#include <hook.h>
#include <kputils.h>
#include <linux/kallsyms.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>

#include "shield_utils.h"

#define TAG "KPM_SHIELD/openat"

#define FSTATAT_NR 79

static int hook_openat_status = 0;
static int hook_faccessat_status = 0;
static int hook_fstatat_status = 0;

static int is_hidden_path(const char *path) {
    if (!path) return 0;
    if (strstr(path, "/memfd:")) return 0;
    return shield_pattern_match(path, g_config.block_paths, g_config.block_paths_count);
}

static int block_if_hidden(const char __user *filename, const char *syscall_name) {
    char buf[256];
    long len;
    if (!filename) return 0;

    len = compat_strncpy_from_user(buf, filename, sizeof(buf));
    if (len <= 0) return 0;

    if (is_hidden_path(buf)) {
        pr_info(TAG ": %s BLOCKED: %s\n", syscall_name, buf);
        return 1;
    }
    return 0;
}

static void before_openat(hook_fargs4_t *args, void *udata) {
    (void)udata;
    if (block_if_hidden((const char __user *)syscall_argn(args, 1), "openat")) {
        args->ret = -2;
        args->skip_origin = 1;
    }
}

static void before_faccessat(hook_fargs3_t *args, void *udata) {
    (void)udata;
    if (block_if_hidden((const char __user *)syscall_argn(args, 1), "faccessat")) {
        args->ret = -2;
        args->skip_origin = 1;
    }
}

static void before_fstatat(hook_fargs4_t *args, void *udata) {
    (void)udata;
    if (block_if_hidden((const char __user *)syscall_argn(args, 1), "fstatat")) {
        args->ret = -2;
        args->skip_origin = 1;
    }
}

int shield_openat_init(void) {
    hook_err_t err;

    err = fp_hook_syscalln(__NR_openat, 4, before_openat, NULL, NULL);
    if (err) {
        pr_err(TAG ": hook openat failed %d\n", err);
    } else {
        hook_openat_status = 1;
    }

    err = fp_hook_syscalln(__NR_faccessat, 3, before_faccessat, NULL, NULL);
    if (err) {
        pr_err(TAG ": hook faccessat failed %d\n", err);
    } else {
        hook_faccessat_status = 1;
    }

    err = fp_hook_syscalln(FSTATAT_NR, 4, before_fstatat, NULL, NULL);
    if (err) {
        pr_err(TAG ": hook fstatat failed %d\n", err);
    } else {
        hook_fstatat_status = 1;
    }

    pr_info(TAG ": openat hide installed (openat/faccessat/fstatat)\n");
    return 0;
}

void shield_openat_exit(void) {
    if (hook_openat_status) {
        fp_unhook_syscalln(__NR_openat, before_openat, NULL);
        hook_openat_status = 0;
    }
    if (hook_faccessat_status) {
        fp_unhook_syscalln(__NR_faccessat, before_faccessat, NULL);
        hook_faccessat_status = 0;
    }
    if (hook_fstatat_status) {
        fp_unhook_syscalln(FSTATAT_NR, before_fstatat, NULL);
        hook_fstatat_status = 0;
    }
    pr_info(TAG ": openat hide uninstalled\n");
}
