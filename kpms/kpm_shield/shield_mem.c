/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * shield_mem.c - Scrub frida signatures from process memory reads.
 * Ported from kpm_frida/mem_hide.c.
 */

#include "shield_mem.h"

#include <compiler.h>
#include <hook.h>
#include <kputils.h>
#include <linux/kallsyms.h>
#include <linux/printk.h>
#include <linux/string.h>

#include "shield_utils.h"

#define TAG "KPM_SHIELD/mem"

static void *access_remote_vm_fn = 0;

/* frida string signatures to zero out */
static const char *frida_signatures[] = {
    "Frida",
    "FRIDA",
    "frida-agent",
    "frida-gadget",
    "frida-server",
    "re.frida.server",
    "libfrida",
};

/* FOLL_WRITE flag (value varies by kernel) */
#ifndef FOLL_WRITE
#define FOLL_WRITE 1
#endif

static void zero_bytes(volatile char *p, int len) {
    for (int i = 0; i < len; i++)
        p[i] = 0;
}

static void scrub_frida_signatures(char *buf, int len) {
    int nsigs = (int)(sizeof(frida_signatures) / sizeof(frida_signatures[0]));

    for (int k = 0; k < nsigs; k++) {
        const char *sig = frida_signatures[k];
        int sig_len = strlen(sig);
        int scan_len = len;

        if (sig_len == 0 || sig_len > scan_len)
            continue;

        for (int i = 0; i <= scan_len - sig_len; i++) {
            if (memcmp(buf + i, sig, sig_len) == 0) {
                zero_bytes((volatile char *)(buf + i), sig_len);
                i += sig_len - 1;
            }
        }
    }
}

static void after_access_remote_vm(hook_fargs5_t *args, void *udata) {
    unsigned int gup_flags = (unsigned int)args->arg4;
    char *buf = (char *)args->arg2;
    int len = (int)args->arg3;

    (void)udata;

    if (gup_flags & FOLL_WRITE)
        return;

    if (args->ret <= 0)
        return;

    if (!buf || len <= 0)
        return;

    if (args->ret < (unsigned long)len)
        len = (int)args->ret;

    scrub_frida_signatures(buf, len);
}

int shield_mem_init(void) {
    access_remote_vm_fn = (void *)kallsyms_lookup_name("access_remote_vm");

    if (access_remote_vm_fn) {
        hook_err_t err = hook_wrap5(access_remote_vm_fn, NULL, after_access_remote_vm, NULL);
        if (err) {
            pr_err(TAG ": hook access_remote_vm failed %d\n", err);
            access_remote_vm_fn = 0;
        }
    } else {
        pr_info(TAG ": access_remote_vm not found, mem hide skipped\n");
    }

    pr_info(TAG ": mem hide installed\n");
    return 0;
}

void shield_mem_exit(void) {
    if (access_remote_vm_fn)
        unhook(access_remote_vm_fn);
    pr_info(TAG ": mem hide uninstalled\n");
}
