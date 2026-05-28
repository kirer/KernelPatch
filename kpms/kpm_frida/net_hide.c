/*
 * net_hide.c - network layer frida hide
 *
 * Hides frida ports from /proc/net/tcp and /proc/net/tcp6
 * via seq_operations->show hook.
 *
 * Note: connect() syscall hook is NOT possible on this kernel
 * because __arm64_sys_connect is not exported in kallsyms.
 * Use iptables rules instead (see ../iptables_frida.sh).
 */

#include "net_hide.h"
#include "common.h"
#include <compiler.h>
#include <hook.h>
#include <kputils.h>
#include <linux/kallsyms.h>
#include <linux/printk.h>
#include <linux/string.h>

struct seq_operations {
    void *(*start)(struct seq_file *m, long long *pos);
    void (*stop)(struct seq_file *m, void *v);
    void *(*next)(struct seq_file *m, void *v, long long *pos);
    int (*show)(struct seq_file *m, void *v);
};

static struct seq_operations *tcp4_seq_ops;
static struct seq_operations *tcp6_seq_ops;
static int (*orig_tcp4_show)(struct seq_file *m, void *v);
static int (*orig_tcp6_show)(struct seq_file *m, void *v);

static int memstr(const char *haystack, size_t max_len, const char *needle) {
    size_t nlen;
    if (!haystack || !needle) return 0;
    nlen = strlen(needle);
    if (nlen == 0 || nlen > max_len) return 0;
    for (size_t i = 0; i + nlen <= max_len; i++)
        if (memcmp(haystack + i, needle, nlen) == 0) return 1;
    return 0;
}

static int is_frida_tcp_line(const char *buf, size_t buf_len) {
    if (!buf || buf_len < 10) return 0;
    if (memstr(buf, buf_len, "local_address")) return 0;
    if (memstr(buf, buf_len, ":69A2") || memstr(buf, buf_len, ":69A3") ||
        memstr(buf, buf_len, ":5D8A") || memstr(buf, buf_len, ":7AB7"))
        return 1;
    return 0;
}

static int kpm_tcp4_show(struct seq_file *m, void *v) {
    size_t start, avail; int ret;
    if (!m) return 0;
    start = m->count;
    ret = orig_tcp4_show(m, v);
    if (!m->buf || m->count <= start || m->count > m->size) return ret;
    avail = m->count - start;
    if (avail > m->size - start) avail = m->size - start;
    if (is_frida_tcp_line(&m->buf[start], avail)) {
        m->count = start;
        pr_info("KPM_FRIDA: /proc/net/tcp hidden frida port line\n");
    }
    return ret;
}

static int kpm_tcp6_show(struct seq_file *m, void *v) {
    size_t start, avail; int ret;
    if (!m) return 0;
    start = m->count;
    ret = orig_tcp6_show(m, v);
    if (!m->buf || m->count <= start || m->count > m->size) return ret;
    avail = m->count - start;
    if (avail > m->size - start) avail = m->size - start;
    if (is_frida_tcp_line(&m->buf[start], avail)) {
        m->count = start;
        pr_info("KPM_FRIDA: /proc/net/tcp6 hidden frida port line\n");
    }
    return ret;
}

void frida_net_hide_install(void) {
    tcp4_seq_ops = (struct seq_operations *)kallsyms_lookup_name("tcp4_seq_ops");
    if (!tcp4_seq_ops) tcp4_seq_ops = (struct seq_operations *)kallsyms_lookup_name("tcp_seq_ops");
    if (tcp4_seq_ops) {
        orig_tcp4_show = tcp4_seq_ops->show;
        fp_hook((uintptr_t)&tcp4_seq_ops->show, (void *)kpm_tcp4_show, (void **)&orig_tcp4_show);
        pr_info("KPM_FRIDA: /proc/net/tcp filter installed\n");
    } else {
        pr_warn("KPM_FRIDA: tcp4_seq_ops not found\n");
    }

    tcp6_seq_ops = (struct seq_operations *)kallsyms_lookup_name("tcp6_seq_ops");
    if (tcp6_seq_ops) {
        orig_tcp6_show = tcp6_seq_ops->show;
        fp_hook((uintptr_t)&tcp6_seq_ops->show, (void *)kpm_tcp6_show, (void **)&orig_tcp6_show);
        pr_info("KPM_FRIDA: /proc/net/tcp6 filter installed\n");
    } else {
        pr_warn("KPM_FRIDA: tcp6_seq_ops not found\n");
    }

    pr_info("KPM_FRIDA: net hide installed (tcp filter only)\n");
}

void frida_net_hide_uninstall(void) {
    if (tcp4_seq_ops) fp_unhook((uintptr_t)&tcp4_seq_ops->show, orig_tcp4_show);
    if (tcp6_seq_ops) fp_unhook((uintptr_t)&tcp6_seq_ops->show, orig_tcp6_show);
    pr_info("KPM_FRIDA: net hide uninstalled\n");
}
