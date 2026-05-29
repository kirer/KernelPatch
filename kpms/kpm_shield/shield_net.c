/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * shield_net.c - Merged network hiding (kpm_hide's hide_net + kpm_frida's net_hide).
 *
 * Single hook on tcp4_seq_ops->show / tcp6_seq_ops->show / unix_seq_ops->show,
 * checking both hide-side and frida-side patterns from g_config.
 */

#include "shield_net.h"
#include "shield_utils.h"

#include <ksyms.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include <hook.h>

#define TAG "KPM_SHIELD/net"

/* ========== kallsyms resolved pointers ========== */

static struct seq_operations *tcp4_seq_ops;
static struct seq_operations *tcp6_seq_ops;
static struct seq_operations *unix_seq_ops;

static int (*orig_tcp4_show)(struct seq_file *m, void *v);
static int (*orig_tcp6_show)(struct seq_file *m, void *v);
static int (*orig_unix_show)(struct seq_file *m, void *v);

/* ========== TCP line filter (merged) ========== */

/*
 * /proc/net/tcp format:
 *   sl  local_address rem_address   st ...
 *   0:  0100007F:31A4 0100007F:XXXX  01 ...
 *
 * Check both:
 *   - address matches configured tcp_addrs
 *   - port matches configured tcp_ports
 */
static int should_hide_tcp_line(const char *line) {
    /* Skip header line */
    if (strstr(line, "local_address"))
        return 0;

    /* Check each configured port pattern */
    for (int i = 0; i < g_config.tcp_ports_count; i++) {
        char port_pattern[SHIELD_MAX_PAT_LEN + 2];
        port_pattern[0] = ':';
        int plen = strlen(g_config.tcp_ports[i]);
        if (plen >= SHIELD_MAX_PAT_LEN) plen = SHIELD_MAX_PAT_LEN - 1;
        memcpy(port_pattern + 1, g_config.tcp_ports[i], plen);
        port_pattern[1 + plen] = '\0';

        if (strstr(line, port_pattern)) {
            /* Also check address if configured */
            if (g_config.tcp_addrs_count == 0)
                return 1;
            for (int j = 0; j < g_config.tcp_addrs_count; j++) {
                if (strstr(line, g_config.tcp_addrs[j]))
                    return 1;
            }
        }
    }
    return 0;
}

/* ========== Unix socket filter (merged) ========== */

static int should_hide_unix_line(const char *line) {
    /* Skip header */
    if (strstr(line, "RefCount"))
        return 0;

    return shield_pattern_match(line, g_config.unix_pat, g_config.unix_pat_count);
}

/* ========== common filtered show ========== */

static int filtered_show(struct seq_file *m, void *v,
                         int (*orig_show)(struct seq_file *, void *),
                         int (*should_hide)(const char *),
                         const char *label) {
    if (!is_app_process())
        return orig_show(m, v);

    size_t start = m->count;
    int ret = orig_show(m, v);
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

    if (should_hide(line)) {
        m->count = start;
        pr_info(TAG ": %s hidden (uid=%d, %zu bytes)\n", label, current_uid(), len);
    }

    kpm_vfree(line);
    return ret;
}

/* ========== hooked show functions ========== */

static int kpm_tcp4_show(struct seq_file *m, void *v) {
    return filtered_show(m, v, orig_tcp4_show, should_hide_tcp_line, "tcp");
}

static int kpm_tcp6_show(struct seq_file *m, void *v) {
    return filtered_show(m, v, orig_tcp6_show, should_hide_tcp_line, "tcp6");
}

static int kpm_unix_show(struct seq_file *m, void *v) {
    return filtered_show(m, v, orig_unix_show, should_hide_unix_line, "unix");
}

/* ========== init / exit ========== */

int shield_net_init(void) {
    /* === /proc/net/tcp === */
    tcp4_seq_ops = (struct seq_operations *)kallsyms_lookup_name("tcp4_seq_ops");
    if (tcp4_seq_ops) {
        orig_tcp4_show = tcp4_seq_ops->show;
        fp_hook((uintptr_t)&tcp4_seq_ops->show, (void *)kpm_tcp4_show,
                (void **)&orig_tcp4_show);
        pr_info(TAG ": tcp4 hook installed (orig=%p)\n", orig_tcp4_show);
    } else {
        pr_info(TAG ": tcp4_seq_ops not found, trying tcp_seq_ops\n");
        tcp4_seq_ops = (struct seq_operations *)kallsyms_lookup_name("tcp_seq_ops");
        if (tcp4_seq_ops) {
            orig_tcp4_show = tcp4_seq_ops->show;
            fp_hook((uintptr_t)&tcp4_seq_ops->show, (void *)kpm_tcp4_show,
                    (void **)&orig_tcp4_show);
            pr_info(TAG ": tcp_seq_ops hook installed (orig=%p)\n", orig_tcp4_show);
        } else {
            pr_info(TAG ": tcp seq_ops not found\n");
        }
    }

    /* === /proc/net/tcp6 === */
    tcp6_seq_ops = (struct seq_operations *)kallsyms_lookup_name("tcp6_seq_ops");
    if (tcp6_seq_ops) {
        orig_tcp6_show = tcp6_seq_ops->show;
        fp_hook((uintptr_t)&tcp6_seq_ops->show, (void *)kpm_tcp6_show,
                (void **)&orig_tcp6_show);
        pr_info(TAG ": tcp6 hook installed (orig=%p)\n", orig_tcp6_show);
    } else {
        pr_info(TAG ": tcp6_seq_ops not found\n");
    }

    /* === /proc/net/unix === */
    unix_seq_ops = (struct seq_operations *)kallsyms_lookup_name("unix_seq_ops");
    if (unix_seq_ops) {
        orig_unix_show = unix_seq_ops->show;
        fp_hook((uintptr_t)&unix_seq_ops->show, (void *)kpm_unix_show,
                (void **)&orig_unix_show);
        pr_info(TAG ": unix hook installed (orig=%p)\n", orig_unix_show);
    } else {
        pr_info(TAG ": unix_seq_ops not found\n");
    }

    return 0;
}

void shield_net_exit(void) {
    if (tcp4_seq_ops && orig_tcp4_show) {
        fp_unhook((uintptr_t)&tcp4_seq_ops->show, orig_tcp4_show);
        pr_info(TAG ": tcp4 hook removed\n");
    }
    if (tcp6_seq_ops && orig_tcp6_show) {
        fp_unhook((uintptr_t)&tcp6_seq_ops->show, orig_tcp6_show);
        pr_info(TAG ": tcp6 hook removed\n");
    }
    if (unix_seq_ops && orig_unix_show) {
        fp_unhook((uintptr_t)&unix_seq_ops->show, orig_unix_show);
        pr_info(TAG ": unix hook removed\n");
    }
}
