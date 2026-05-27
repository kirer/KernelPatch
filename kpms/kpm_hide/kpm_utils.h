/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_UTILS_H
#define _KPM_UTILS_H

#include <ktypes.h>
#include <ksyms.h>
#include <kputils.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <stdbool.h>

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

/* ========== shared init (call once from kpm_tools_init) ========== */

static inline int kpm_utils_init(void) {
    kpm_vmalloc = (typeof(kpm_vmalloc))kallsyms_lookup_name("vmalloc");
    kpm_vfree = (typeof(kpm_vfree))kallsyms_lookup_name("vfree");
    kpm_arch_copy_from_user = (typeof(kpm_arch_copy_from_user))kallsyms_lookup_name("__arch_copy_from_user");
    if (!kpm_vmalloc || !kpm_vfree) {
        return -1;
    }
    return 0;
}

#endif /* _KPM_UTILS_H */
