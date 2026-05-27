/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * hide_maps.c - Hide injection artifacts from /proc/<pid>/maps and smaps.
 *
 * Hooks proc_pid_maps_op->show and proc_pid_smaps_op->show.
 * After the original show writes a line into seq_file, we inspect it
 * and rollback m->count if the line matches a filter pattern.
 */

#include "hide_maps.h"
#include "kpm_utils.h"

#include <ksyms.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include <hook.h>

#define TAG "KPM_HIDE/maps"

/* ========== kallsyms resolved pointers ========== */

static struct seq_operations *proc_pid_maps_op;
static struct seq_operations *proc_pid_smaps_op;
static int (*orig_show_map)(struct seq_file *m, void *v);
static int (*orig_show_smap)(struct seq_file *m, void *v);

/* ========== maps line filter ========== */

static int should_hide_line(const char *line) {
    /* 1. memfd marker used by the loader */
    if (strstr(line, "/memfd:wwb"))
        return 1;

    /* 2. Hook pool marker named via prctl(PR_SET_VMA_ANON_NAME, ...) */
    if (strstr(line, "[anon:wwb]"))
        return 1;

    return 0;
}

/* ========== hooked show functions ========== */

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

    if (should_hide_line(line)) {
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

    if (should_hide_line(line)) {
        m->count = start;
        pr_info(TAG ": smaps hidden (uid=%d, %zu bytes)\n", current_uid(), len);
    }

    kpm_vfree(line);
    return ret;
}

/* ========== init / exit ========== */

int hide_maps_init(void) {
    /* Resolve proc_pid_maps_op */
    proc_pid_maps_op = (struct seq_operations *)kallsyms_lookup_name("proc_pid_maps_op");
    if (!proc_pid_maps_op) {
        pr_info(TAG ": proc_pid_maps_op not found\n");
        return -1;
    }
    orig_show_map = proc_pid_maps_op->show;

    /* Resolve proc_pid_smaps_op */
    proc_pid_smaps_op = (struct seq_operations *)kallsyms_lookup_name("proc_pid_smaps_op");
    if (proc_pid_smaps_op)
        orig_show_smap = proc_pid_smaps_op->show;

    /* Install hooks */
    fp_hook((uintptr_t)&proc_pid_maps_op->show, (void *)kpm_show_map,
            (void **)&orig_show_map);
    pr_info(TAG ": maps hook installed (orig=%p)\n", orig_show_map);

    if (proc_pid_smaps_op && orig_show_smap) {
        fp_hook((uintptr_t)&proc_pid_smaps_op->show, (void *)kpm_show_smap,
                (void **)&orig_show_smap);
        pr_info(TAG ": smaps hook installed (orig=%p)\n", orig_show_smap);
    }

    return 0;
}

void hide_maps_exit(void) {
    if (proc_pid_maps_op && orig_show_map) {
        fp_unhook((uintptr_t)&proc_pid_maps_op->show, orig_show_map);
        pr_info(TAG ": maps hook removed\n");
    }
    if (proc_pid_smaps_op && orig_show_smap) {
        fp_unhook((uintptr_t)&proc_pid_smaps_op->show, orig_show_smap);
        pr_info(TAG ": smaps hook removed\n");
    }
}
