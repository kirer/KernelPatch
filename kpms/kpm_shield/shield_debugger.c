/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * shield_debugger.c - Debugger trace hiding.
 * Ported from kpm_frida/debugger_hide.c.
 *
 * Hides:
 *   - /proc/pid/status TracerPid → 0
 *   - /proc/pid/status state → "S (sleeping)" instead of "t (tracing stop)"
 *   - /proc/pid/wchan → "0" instead of "ptrace_stop"
 *   - /proc/pid/stat state → 'S' instead of 't'
 */

#include "shield_debugger.h"

#include <ktypes.h>
#include <hook.h>
#include <kputils.h>
#include <syscall.h>

#include <linux/printk.h>
#include <linux/kallsyms.h>
#include <linux/string.h>

#include "shield_utils.h"

#define TAG "KPM_SHIELD/debugger"

static void *seq_put_decimal_ull_fn = 0;
static void *seq_puts_fn = 0;
static void *proc_pid_wchan_fn = 0;
static void *do_task_stat_fn = 0;

/* /proc/[pid]/status -> TracerPid: 0 */
static void before_seq_put_decimal_ull(hook_fargs3_t *args, void *udata) {
    const char *s = (const char *)args->arg1;
    (void)udata;
    if (!s) return;
    if (strcmp(s, "\nTracerPid:\t") == 0 && args->arg2 != 0) {
        args->arg2 = 0;
    }
}

/* /proc/[pid]/status -> S (sleeping) instead of t (tracing stop) */
static void before_seq_puts(hook_fargs2_t *args, void *udata) {
    const char *s = (const char *)args->arg1;
    (void)udata;
    if (!s) return;
    if (strcmp(s, "t (tracing stop)") == 0) {
        args->arg1 = (uint64_t)"S (sleeping)";
    }
}

/* /proc/[pid]/wchan -> 0 instead of ptrace_stop */
static void after_proc_pid_wchan(hook_fargs4_t *args, void *udata) {
    struct seq_file *m = (struct seq_file *)args->arg0;
    (void)udata;
    if (!m || !m->buf || m->count < 2) return;
    if (strncmp((char *)m->buf, "ptrace_stop", m->count) == 0) {
        m->buf[0] = '0';
        m->buf[1] = '\0';
        m->count = 1;
    }
}

/* /proc/[pid]/stat state -> 'S' instead of 't' */
static void after_do_task_stat(hook_fargs5_t *args, void *udata) {
    struct seq_file *m = (struct seq_file *)args->arg0;
    (void)udata;
    if (!m || !m->buf) return;
    for (size_t i = 0; i + 2 < m->count; i++) {
        if (m->buf[i] == ')' && m->buf[i + 1] == ' ') {
            if (m->buf[i + 2] == 't')
                m->buf[i + 2] = 'S';
            break;
        }
    }
}

int shield_debugger_init(void) {
    seq_put_decimal_ull_fn = (void *)kallsyms_lookup_name("seq_put_decimal_ull");
    seq_puts_fn = (void *)kallsyms_lookup_name("seq_puts");
    proc_pid_wchan_fn = (void *)kallsyms_lookup_name("proc_pid_wchan");
    do_task_stat_fn = (void *)kallsyms_lookup_name("do_task_stat");

    if (seq_put_decimal_ull_fn) {
        hook_err_t err = hook_wrap3(seq_put_decimal_ull_fn, before_seq_put_decimal_ull, NULL, NULL);
        if (err) {
            pr_err(TAG ": hook seq_put_decimal_ull failed %d\n", err);
            seq_put_decimal_ull_fn = 0;
        }
    } else {
        pr_info(TAG ": seq_put_decimal_ull not found\n");
    }

    if (seq_puts_fn) {
        hook_err_t err = hook_wrap2(seq_puts_fn, before_seq_puts, NULL, NULL);
        if (err) {
            pr_err(TAG ": hook seq_puts failed %d\n", err);
            seq_puts_fn = 0;
        }
    } else {
        pr_info(TAG ": seq_puts not found\n");
    }

    if (proc_pid_wchan_fn) {
        hook_err_t err = hook_wrap4(proc_pid_wchan_fn, NULL, after_proc_pid_wchan, NULL);
        if (err) {
            pr_err(TAG ": hook proc_pid_wchan failed %d\n", err);
            proc_pid_wchan_fn = 0;
        }
    } else {
        pr_info(TAG ": proc_pid_wchan not found\n");
    }

    if (do_task_stat_fn) {
        hook_err_t err = hook_wrap5(do_task_stat_fn, NULL, after_do_task_stat, NULL);
        if (err) {
            pr_err(TAG ": hook do_task_stat failed %d\n", err);
            do_task_stat_fn = 0;
        }
    } else {
        pr_info(TAG ": do_task_stat not found\n");
    }

    pr_info(TAG ": debugger hide installed\n");
    return 0;
}

void shield_debugger_exit(void) {
    if (seq_put_decimal_ull_fn) unhook(seq_put_decimal_ull_fn);
    if (seq_puts_fn) unhook(seq_puts_fn);
    if (proc_pid_wchan_fn) unhook(proc_pid_wchan_fn);
    if (do_task_stat_fn) unhook(do_task_stat_fn);
    pr_info(TAG ": debugger hide uninstalled\n");
}
