/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * shield_apatch.c - Bypass APatch's syscall hook chain for excluded processes.
 *
 * Ported from kpm_hide/hide_apatch.c.
 * Replaces sys_call_table entries with wrapper functions that check
 * get_ap_mod_exclude(uid). For excluded processes, the wrapper calls
 * the original kernel syscall directly (bypassing APatch/KP hooks).
 */

#include <asm/current.h>
#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <ktypes.h>
#include <linux/cred.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <pgtable.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>
#include <sucompat.h>

#include "shield_utils.h"

#define TAG "KPM_SHIELD/apatch"

/* KernelPatch exported symbols */
extern uintptr_t *sys_call_table;
extern uintptr_t *compat_sys_call_table;
extern int has_syscall_wrapper;

/* ========== types ========== */

typedef long (*syscall_wrapper_f)(struct pt_regs *regs);

/* 32-bit compat syscall numbers */
#define COMPAT_NR_execve      11
#define COMPAT_NR_fstatat64   327
#define COMPAT_NR_faccessat   334

struct sct_entry {
    int nr;
    uintptr_t orig_addr;
    uintptr_t kp_chain;
    int replaced;
    int is_compat;
};

/* ========== 64-bit syscall replacement table ========== */

static struct sct_entry sct_entries[] = {
    { __NR3264_truncate, 0, 0, 0, 0 },
    { __NR_execve,       0, 0, 0, 0 },
    { __NR3264_fstatat,  0, 0, 0, 0 },
    { __NR_faccessat,    0, 0, 0, 0 },
    { __NR_statx,        0, 0, 0, 0 },
    /* side-channel decoys: write-class syscalls */
    { __NR_unlinkat,     0, 0, 0, 0 },
    { __NR_mkdirat,      0, 0, 0, 0 },
    { __NR_mknodat,      0, 0, 0, 0 },
    { __NR_linkat,       0, 0, 0, 0 },
    { __NR_symlinkat,    0, 0, 0, 0 },
    { __NR_renameat2,    0, 0, 0, 0 },
    { __NR_fchmodat,     0, 0, 0, 0 },
    { __NR_fchownat,     0, 0, 0, 0 },
    { __NR_utimensat,    0, 0, 0, 0 },
};
#define SCT_ENTRY_COUNT (sizeof(sct_entries) / sizeof(sct_entries[0]))

/* ========== 32-bit compat syscall replacement table ========== */

static struct sct_entry sct_compat_entries[] = {
    { COMPAT_NR_execve,    0, 0, 0, 1 },
    { COMPAT_NR_fstatat64, 0, 0, 0, 1 },
    { COMPAT_NR_faccessat, 0, 0, 0, 1 },
};
#define SCT_COMPAT_ENTRY_COUNT (sizeof(sct_compat_entries) / sizeof(sct_compat_entries[0]))

/* ========== entry lookup ========== */

static struct sct_entry *find_sct_entry(int nr, int is_compat) {
    if (is_compat) {
        for (int i = 0; i < SCT_COMPAT_ENTRY_COUNT; i++) {
            if (sct_compat_entries[i].nr == nr) return &sct_compat_entries[i];
        }
    } else {
        for (int i = 0; i < SCT_ENTRY_COUNT; i++) {
            if (sct_entries[i].nr == nr) return &sct_entries[i];
        }
    }
    return NULL;
}

/* ========== dispatch logic ========== */

static long sct_generic_dispatch(struct pt_regs *regs, struct sct_entry *e) {
    uid_t uid = current_uid();
    int exclude = get_ap_mod_exclude(uid);
    if (exclude && e->orig_addr) {
        return ((syscall_wrapper_f)e->orig_addr)(regs);
    }
    return ((syscall_wrapper_f)e->kp_chain)(regs);
}

static long sct_debug_ramdisk_dispatch(struct pt_regs *regs, struct sct_entry *e) {
    uid_t uid = current_uid();
    int exclude = get_ap_mod_exclude(uid);
    if (exclude && e->orig_addr) {
        long ret = ((syscall_wrapper_f)e->orig_addr)(regs);
        if (ret == 0 && uid > 10000) {
            const char __user *pathname = (const char __user *)regs->regs[1];
            char path_buf[64];
            compat_strncpy_from_user(path_buf, pathname, sizeof(path_buf));
            if (strcmp(path_buf, "/debug_ramdisk") == 0) {
                return -2; /* -ENOENT */
            }
        }
        return ret;
    }
    return ((syscall_wrapper_f)e->kp_chain)(regs);
}

/* ========== per-syscall wrapper definitions ========== */

#define DEFINE_SCT_WRAPPER(name, nr, compat) \
    static long sct_##name##_wrapper(struct pt_regs *regs) { \
        struct sct_entry *e = find_sct_entry(nr, compat); \
        return sct_generic_dispatch(regs, e); \
    }

#define DEFINE_SCT_WRAPPER_DEBUG_RAMDISK(name, nr, compat) \
    static long sct_##name##_wrapper(struct pt_regs *regs) { \
        struct sct_entry *e = find_sct_entry(nr, compat); \
        return sct_debug_ramdisk_dispatch(regs, e); \
    }

/* 64-bit wrappers */
DEFINE_SCT_WRAPPER(truncate, __NR3264_truncate, 0)
DEFINE_SCT_WRAPPER(execve, __NR_execve, 0)
DEFINE_SCT_WRAPPER_DEBUG_RAMDISK(fstatat, __NR3264_fstatat, 0)
DEFINE_SCT_WRAPPER_DEBUG_RAMDISK(faccessat, __NR_faccessat, 0)
DEFINE_SCT_WRAPPER_DEBUG_RAMDISK(statx, __NR_statx, 0)

/* decoys */
DEFINE_SCT_WRAPPER(unlinkat, __NR_unlinkat, 0)
DEFINE_SCT_WRAPPER(mkdirat, __NR_mkdirat, 0)
DEFINE_SCT_WRAPPER(mknodat, __NR_mknodat, 0)
DEFINE_SCT_WRAPPER(linkat, __NR_linkat, 0)
DEFINE_SCT_WRAPPER(symlinkat, __NR_symlinkat, 0)
DEFINE_SCT_WRAPPER(renameat2, __NR_renameat2, 0)
DEFINE_SCT_WRAPPER(fchmodat, __NR_fchmodat, 0)
DEFINE_SCT_WRAPPER(fchownat, __NR_fchownat, 0)
DEFINE_SCT_WRAPPER(utimensat, __NR_utimensat, 0)

/* 32-bit compat wrappers */
DEFINE_SCT_WRAPPER(compat_execve, COMPAT_NR_execve, 1)
DEFINE_SCT_WRAPPER_DEBUG_RAMDISK(compat_fstatat, COMPAT_NR_fstatat64, 1)
DEFINE_SCT_WRAPPER_DEBUG_RAMDISK(compat_faccessat, COMPAT_NR_faccessat, 1)

/* Wrapper function pointer tables (must match sct_entries order) */
static syscall_wrapper_f sct_wrappers[] = {
    sct_truncate_wrapper,
    sct_execve_wrapper,
    sct_fstatat_wrapper,
    sct_faccessat_wrapper,
    sct_statx_wrapper,
    sct_unlinkat_wrapper,
    sct_mkdirat_wrapper,
    sct_mknodat_wrapper,
    sct_linkat_wrapper,
    sct_symlinkat_wrapper,
    sct_renameat2_wrapper,
    sct_fchmodat_wrapper,
    sct_fchownat_wrapper,
    sct_utimensat_wrapper,
};

static syscall_wrapper_f sct_compat_wrappers[] = {
    sct_compat_execve_wrapper,
    sct_compat_fstatat_wrapper,
    sct_compat_faccessat_wrapper,
};

/* ========== page table manipulation ========== */

static uint64_t cached_pgd_va = 0;

static void sct_init_pgd(void) {
    if (cached_pgd_va) return;
    cached_pgd_va = (uint64_t)kallsyms_lookup_name("swapper_pg_dir");
    pr_info(TAG ": swapper_pg_dir: %llx\n", cached_pgd_va);
}

static void sct_write_entry(uintptr_t *table, int nr, uintptr_t new_val, uintptr_t *backup) {
    if (!cached_pgd_va) {
        pr_info(TAG ": sct_write: pgd not initialized\n");
        return;
    }
    uint64_t addr = (uint64_t)&table[nr];
    uint64_t *pte = pgtable_entry(cached_pgd_va, addr);
    if (!pte) {
        pr_info(TAG ": sct_write: pgtable_entry failed for %llx\n", addr);
        return;
    }
    uint64_t ori_prot = *pte;

    *pte = (ori_prot | PTE_DBM) & ~PTE_RDONLY;
    flush_tlb_kernel_page(addr);

    if (backup) {
        *backup = table[nr];
    }
    table[nr] = new_val;
    dsb(ish);

    *pte = ori_prot;
    flush_tlb_kernel_page(addr);
}

static void sct_restore_entry(uintptr_t *table, int nr, uintptr_t old_val) {
    if (!cached_pgd_va) return;
    uint64_t addr = (uint64_t)&table[nr];
    uint64_t *pte = pgtable_entry(cached_pgd_va, addr);
    if (!pte) return;
    uint64_t ori_prot = *pte;

    *pte = (ori_prot | PTE_DBM) & ~PTE_RDONLY;
    flush_tlb_kernel_page(addr);

    table[nr] = old_val;
    dsb(ish);

    *pte = ori_prot;
    flush_tlb_kernel_page(addr);
}

/* ========== resolve original kernel syscall addresses ========== */

static void cache_origin_syscall_addrs(void) {
    for (int i = 0; i < SCT_ENTRY_COUNT; i++) {
        sct_entries[i].orig_addr = syscalln_name_addr(sct_entries[i].nr, 0);
    }
    for (int i = 0; i < SCT_COMPAT_ENTRY_COUNT; i++) {
        sct_compat_entries[i].orig_addr = syscalln_name_addr(sct_compat_entries[i].nr, 1);
    }
}

/* ========== init / exit ========== */

int shield_apatch_init(void) {
    sct_init_pgd();
    cache_origin_syscall_addrs();

    if (!sys_call_table) {
        pr_info(TAG ": sys_call_table is NULL, skip\n");
        return -1;
    }
    if (!has_syscall_wrapper) {
        pr_info(TAG ": no syscall_wrapper, skip\n");
        return -1;
    }

    for (int i = 0; i < SCT_ENTRY_COUNT; i++) {
        struct sct_entry *e = &sct_entries[i];
        sct_write_entry(sys_call_table, e->nr,
                        (uintptr_t)sct_wrappers[i], &e->kp_chain);
        e->replaced = 1;
        pr_info(TAG ": replaced nr=%d kp_chain=%llx orig=%llx\n",
                e->nr, (uint64_t)e->kp_chain, (uint64_t)e->orig_addr);
    }

    if (compat_sys_call_table) {
        for (int i = 0; i < SCT_COMPAT_ENTRY_COUNT; i++) {
            struct sct_entry *e = &sct_compat_entries[i];
            sct_write_entry(compat_sys_call_table, e->nr,
                            (uintptr_t)sct_compat_wrappers[i], &e->kp_chain);
            e->replaced = 1;
            pr_info(TAG ": replaced compat nr=%d kp_chain=%llx\n",
                    e->nr, (uint64_t)e->kp_chain);
        }
    }

    pr_info(TAG ": sys_call_table replacement installed\n");
    return 0;
}

void shield_apatch_exit(void) {
    for (int i = 0; i < SCT_ENTRY_COUNT; i++) {
        struct sct_entry *e = &sct_entries[i];
        if (e->replaced) {
            sct_restore_entry(sys_call_table, e->nr, e->kp_chain);
            e->replaced = 0;
        }
    }
    for (int i = 0; i < SCT_COMPAT_ENTRY_COUNT; i++) {
        struct sct_entry *e = &sct_compat_entries[i];
        if (e->replaced) {
            sct_restore_entry(compat_sys_call_table, e->nr, e->kp_chain);
            e->replaced = 0;
        }
    }
    pr_info(TAG ": sys_call_table replacement removed\n");
}
