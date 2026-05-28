/*
 * openat_hide.c - block Frida file probes via openat, faccessat, fstatat
 */

#include "openat_hide.h"

#include <compiler.h>
#include <hook.h>
#include <kputils.h>
#include <linux/kallsyms.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>

#include "common.h"

/* arm64 fstatat = 79, covers stat/lstat/fstatat */
#define FSTATAT_NR 79

static int hook_openat_status = 0;
static int hook_faccessat_status = 0;
static int hook_fstatat_status = 0;

static int is_hidden_path(const char *path)
{
    const char *block_paths[] = {
        "re.frida.server",
        "frida-agent-32.so",
        "frida-agent-64.so",
        "frida-agent.so",
        "frida-gadget",
        "linjector",
    };

    if (!path)
        return 0;

    if (strstr(path, "/memfd:"))
        return 0;

    for (int i = 0; i < (int)(sizeof(block_paths) / sizeof(block_paths[0])); i++) {
        if (strstr(path, block_paths[i]))
            return 1;
    }

    return 0;
}

static int block_if_hidden(const char __user *filename, const char *syscall_name)
{
    char buf[256];
    long len;

    if (!filename)
        return 0;

    len = compat_strncpy_from_user(buf, filename, sizeof(buf));
    if (len <= 0)
        return 0;

    if (is_hidden_path(buf)) {
        pr_info("KPM_FRIDA: %s BLOCKED: %s\n", syscall_name, buf);
        return 1;
    }

    return 0;
}

static void before_openat(hook_fargs4_t *args, void *udata)
{
    (void)udata;

    if (block_if_hidden((const char __user *)syscall_argn(args, 1), "openat")) {
        args->ret = -2;
        args->skip_origin = 1;
    }
}

static void before_faccessat(hook_fargs3_t *args, void *udata)
{
    (void)udata;

    if (block_if_hidden((const char __user *)syscall_argn(args, 1), "faccessat")) {
        args->ret = -2;
        args->skip_origin = 1;
    }
}

static void before_fstatat(hook_fargs4_t *args, void *udata)
{
    (void)udata;

    if (block_if_hidden((const char __user *)syscall_argn(args, 1), "fstatat")) {
        args->ret = -2;
        args->skip_origin = 1;
    }
}

void frida_openat_hide_install(void)
{
    hook_err_t err;

    err = fp_hook_syscalln(__NR_openat, 4, before_openat, NULL, NULL);
    if (err) {
        pr_err("KPM_FRIDA: hook openat failed %d\n", err);
    } else {
        hook_openat_status = 1;
    }

    err = fp_hook_syscalln(__NR_faccessat, 3, before_faccessat, NULL, NULL);
    if (err) {
        pr_err("KPM_FRIDA: hook faccessat failed %d\n", err);
    } else {
        hook_faccessat_status = 1;
    }

    err = fp_hook_syscalln(FSTATAT_NR, 4, before_fstatat, NULL, NULL);
    if (err) {
        pr_err("KPM_FRIDA: hook fstatat failed %d\n", err);
    } else {
        hook_fstatat_status = 1;
    }

    pr_info("KPM_FRIDA: openat hide installed (openat/faccessat/fstatat)\n");
}

void frida_openat_hide_uninstall(void)
{
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

    pr_info("KPM_FRIDA: openat hide uninstalled\n");
}
