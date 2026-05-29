/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * shield_maps.c - Merged maps hiding.
 *
 * Layer 1: proc_pid_maps_op->show / proc_pid_smaps_op->show hook
 *          (from kpm_hide's hide_maps.c) — hides injection artifacts.
 * Layer 2: show_map_vma hook (from kpm_frida's frida_hide.c) — hides
 *          frida-related VMA names within each maps line.
 * Layer 3: __get_task_comm hook — disguises frida thread names in
 *          /proc/pid/status and /proc/pid/stat.
 *
 * All filters use the unified maps_pat and comm_pat from g_config.
 */

#include "shield_maps.h"
#include "shield_utils.h"

#include <ksyms.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include <hook.h>

#define TAG "KPM_SHIELD/maps"

/* ========== Layer 1: proc_pid_maps_op / proc_pid_smaps_op hook ========== */

static struct seq_operations *proc_pid_maps_op;
static struct seq_operations *proc_pid_smaps_op;
static int (*orig_show_map)(struct seq_file *m, void *v);
static int (*orig_show_smap)(struct seq_file *m, void *v);

static int kpm_show_map(struct seq_file *m, void *v) {
    if (!is_app_process())
        return orig_show_map(m, v);

    size_t start = m->count;
    int ret = orig_show_map(m, v);
    size_t end = m->count;

    if (end <= start || !kpm_vmalloc)
        return ret;

    size_t len = end - start;
    char *line = kpm_vmalloc(len + 1);
    if (!line)
        return ret;

    for (size_t i = 0; i < len; i++)
        line[i] = m->buf[start + i];
    line[len] = '\0';

    if (shield_pattern_match(line, g_config.maps_pat, g_config.maps_pat_count)) {
        m->count = start;
        pr_info(TAG ": maps hidden (uid=%d, %zu bytes)\n", current_uid(), len);
    }

    kpm_vfree(line);
    return ret;
}

static int kpm_show_smap(struct seq_file *m, void *v) {
    if (!is_app_process())
        return orig_show_smap(m, v);

    size_t start = m->count;
    int ret = orig_show_smap(m, v);
    size_t end = m->count;

    if (end <= start || !kpm_vmalloc)
        return ret;

    size_t len = end - start;
    char *line = kpm_vmalloc(len + 1);
    if (!line)
        return ret;

    for (size_t i = 0; i < len; i++)
        line[i] = m->buf[start + i];
    line[len] = '\0';

    if (shield_pattern_match(line, g_config.maps_pat, g_config.maps_pat_count)) {
        m->count = start;
        pr_info(TAG ": smaps hidden (uid=%d, %zu bytes)\n", current_uid(), len);
    }

    kpm_vfree(line);
    return ret;
}

/* ========== Layer 2: show_map_vma hook (intra-line frida hiding) ========== */

static void *show_map_vma_fn = 0;

static int contains_token(const char *buf, size_t len, const char *token) {
    size_t token_len;
    if (!buf || !token) return 0;
    token_len = strlen(token);
    if (token_len == 0 || len < token_len) return 0;
    for (size_t i = 0; i + token_len <= len; ++i) {
        if (!memcmp(buf + i, token, token_len))
            return 1;
    }
    return 0;
}

static int __attribute__((optimize("O0"))) is_hidden_vma(struct seq_file *m, size_t prev_count) {
    const char *start;
    size_t new_len;

    if (!m || !m->buf || m->count < prev_count) return 0;
    if (prev_count > m->size) return 0;

    start = m->buf + prev_count;
    new_len = m->count - prev_count;
    if (new_len == 0) return 0;

    if (prev_count + new_len > m->size)
        new_len = m->size - prev_count;

    for (int i = 0; i < g_config.maps_pat_count; i++) {
        if (contains_token(start, new_len, g_config.maps_pat[i]))
            return 1;
    }
    return 0;
}

static void before_show_map_vma(hook_fargs2_t *args, void *udata) {
    struct seq_file *m = (struct seq_file *)args->arg0;
    (void)udata;
    if (m && m->buf) {
        args->local.data0 = m->count;
        args->local.data1 = 1;
    } else {
        args->local.data1 = 0;
    }
}

static void after_show_map_vma(hook_fargs2_t *args, void *udata) {
    struct seq_file *m = (struct seq_file *)args->arg0;
    (void)udata;
    if (m && m->buf && args->local.data1) {
        size_t prev_count = (size_t)args->local.data0;
        if (is_hidden_vma(m, prev_count))
            m->count = prev_count;
    }
}

/* ========== Layer 3: __get_task_comm hook ========== */

static void *get_task_comm_fn = 0;

static void __attribute__((optimize("O0"))) after_get_task_comm(hook_fargs3_t *args, void *udata) {
    char *comm = (char *)args->arg0;
    size_t comm_buf_len = (size_t)args->arg1;
    const char *fake = "binder";
    size_t copy_len;

    (void)udata;

    if (!comm || comm_buf_len == 0) return;
    if (!shield_pattern_match(comm, g_config.comm_pat, g_config.comm_pat_count))
        return;

    copy_len = strlen(fake);
    if (copy_len >= comm_buf_len)
        copy_len = comm_buf_len - 1;

    memcpy(comm, fake, copy_len);
    comm[copy_len] = '\0';
}

/* ========== init / exit ========== */

int shield_maps_init(void) {
    /* Layer 1: proc_pid_maps_op->show */
    proc_pid_maps_op = (struct seq_operations *)kallsyms_lookup_name("proc_pid_maps_op");
    if (!proc_pid_maps_op) {
        pr_info(TAG ": proc_pid_maps_op not found\n");
    } else {
        orig_show_map = proc_pid_maps_op->show;
        fp_hook((uintptr_t)&proc_pid_maps_op->show, (void *)kpm_show_map,
                (void **)&orig_show_map);
        pr_info(TAG ": maps hook installed (orig=%p)\n", orig_show_map);
    }

    /* Layer 1b: proc_pid_smaps_op->show */
    proc_pid_smaps_op = (struct seq_operations *)kallsyms_lookup_name("proc_pid_smaps_op");
    if (proc_pid_smaps_op) {
        orig_show_smap = proc_pid_smaps_op->show;
        fp_hook((uintptr_t)&proc_pid_smaps_op->show, (void *)kpm_show_smap,
                (void **)&orig_show_smap);
        pr_info(TAG ": smaps hook installed (orig=%p)\n", orig_show_smap);
    }

    /* Layer 2: show_map_vma */
    show_map_vma_fn = (void *)kallsyms_lookup_name("show_map_vma");
    if (show_map_vma_fn) {
        hook_err_t err = hook_wrap2(show_map_vma_fn, before_show_map_vma, after_show_map_vma, NULL);
        if (err) {
            pr_err(TAG ": hook show_map_vma failed %d\n", err);
            show_map_vma_fn = 0;
        } else {
            pr_info(TAG ": show_map_vma hook installed\n");
        }
    } else {
        pr_info(TAG ": show_map_vma not found\n");
    }

    /* Layer 3: __get_task_comm (only if feat_comm enabled) */
    get_task_comm_fn = (void *)kallsyms_lookup_name("__get_task_comm");
    if (get_task_comm_fn && g_config.feat_comm) {
        hook_err_t err = hook_wrap3(get_task_comm_fn, NULL, after_get_task_comm, NULL);
        if (err) {
            pr_err(TAG ": hook __get_task_comm failed %d\n", err);
            get_task_comm_fn = 0;
        } else {
            pr_info(TAG ": __get_task_comm hook installed\n");
        }
    }

    return 0;
}

void shield_maps_exit(void) {
    if (proc_pid_maps_op && orig_show_map) {
        fp_unhook((uintptr_t)&proc_pid_maps_op->show, orig_show_map);
        pr_info(TAG ": maps hook removed\n");
    }
    if (proc_pid_smaps_op && orig_show_smap) {
        fp_unhook((uintptr_t)&proc_pid_smaps_op->show, orig_show_smap);
        pr_info(TAG ": smaps hook removed\n");
    }
    if (show_map_vma_fn) {
        unhook(show_map_vma_fn);
        pr_info(TAG ": show_map_vma hook removed\n");
    }
    if (get_task_comm_fn) {
        unhook(get_task_comm_fn);
        pr_info(TAG ": __get_task_comm hook removed\n");
    }
}
