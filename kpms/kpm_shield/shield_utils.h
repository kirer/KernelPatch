/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _SHIELD_UTILS_H
#define _SHIELD_UTILS_H

#include <ktypes.h>
#include <ksyms.h>
#include <kputils.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <stdbool.h>

#include "shield_config.h"

/* ========== vmalloc / vfree (resolved at runtime) ========== */

extern void *(*kpm_vmalloc)(unsigned long size);
extern void (*kpm_vfree)(void *ptr);
extern int (*kpm_arch_copy_from_user)(void *to, const void __user *from, unsigned long n);

/* ========== shared process filter ========== */

static inline int is_app_process(void) {
    uid_t uid = current_uid();
    return uid > 10000;
}

/* ========== string helpers ========== */

static inline bool ends_with(const char *buf, size_t buf_size, const char *suffix) {
    size_t suffix_len = strlen(suffix);
    size_t buf_len = strnlen(buf, buf_size);
    if (buf_len < suffix_len)
        return false;
    return (memcmp(buf + (buf_len - suffix_len), suffix, suffix_len) == 0);
}

/* ========== seq_file minimal definition ========== */

typedef struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
    size_t pad_until;
    long long index;
    long long read_pos;
} seq_file;

struct seq_operations {
    void *(*start)(struct seq_file *m, long long *pos);
    void (*stop)(struct seq_file *m, void *v);
    void *(*next)(struct seq_file *m, void *v, long long *pos);
    int (*show)(struct seq_file *m, void *v);
};

/* ========== shared init (call once from shield_main) ========== */

static inline int shield_utils_init(void) {
    kpm_vmalloc = (typeof(kpm_vmalloc))kallsyms_lookup_name("vmalloc");
    kpm_vfree = (typeof(kpm_vfree))kallsyms_lookup_name("vfree");
    kpm_arch_copy_from_user = (typeof(kpm_arch_copy_from_user))kallsyms_lookup_name("__arch_copy_from_user");
    if (!kpm_vmalloc || !kpm_vfree) {
        return -1;
    }
    return 0;
}

#endif /* _SHIELD_UTILS_H */
