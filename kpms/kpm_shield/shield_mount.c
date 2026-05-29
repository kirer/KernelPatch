/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * shield_mount.c - Hide APatch/zygisk mount points.
 * Ported from kpm_hide/hide_mount.c.
 * Uses configurable mount_pat from g_config.
 */

#include <compiler.h>
#include <hook.h>
#include <kputils.h>
#include <ksyms.h>
#include <ktypes.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <stdbool.h>

#include "shield_utils.h"

#define TAG "KPM_SHIELD/mount"

/* ========== mount ID rewriting state ========== */

#define MAX_PEER_GROUPS  256
#define MAX_MOUNT_ENTRIES 512

static struct {
    void *seq;
    int last_id;
    int delta;
    int map_old[MAX_MOUNT_ENTRIES];
    int map_new[MAX_MOUNT_ENTRIES];
    int map_count;
    int redir_hidden[MAX_MOUNT_ENTRIES];
    int redir_parent[MAX_MOUNT_ENTRIES];
    int redir_count;
    int pg_old[MAX_PEER_GROUPS];
    int pg_new[MAX_PEER_GROUPS];
    int pg_count;
    int pg_next;
} mt_id_state;

/* ========== resolved kernel symbols ========== */

static void *fn_show_vfsmnt = 0;
static void *fn_show_mountinfo = 0;
static void *fn_show_vfsstat = 0;

/* ========== mount filter ========== */

static bool should_hide_mount(char *line) {
    return shield_pattern_match(line, g_config.mount_pat, g_config.mount_pat_count);
}

/* ========== mount ID rewriting helpers ========== */

static int parse_first_int(const char *s) {
    int val = 0;
    while (*s >= '0' && *s <= '9') {
        val = val * 10 + (*s - '0');
        s++;
    }
    return val;
}

static int write_int_to_buf(char *buf, int val) {
    if (val <= 0) {
        buf[0] = '0';
        return 1;
    }
    char tmp[12];
    int len = 0;
    int v = val;
    while (v > 0) {
        tmp[len++] = '0' + (v % 10);
        v /= 10;
    }
    for (int i = 0; i < len; i++)
        buf[i] = tmp[len - 1 - i];
    return len;
}

static int rewrite_int_at(seq_file *m, int pos, int old_val, int new_val) {
    if (pos < 0 || (size_t)pos >= m->count) return 0;
    char *p = m->buf + pos;
    int old_len = 0;
    while ((size_t)(pos + old_len) < m->count && p[old_len] >= '0' && p[old_len] <= '9')
        old_len++;
    if (old_len == 0) return 0;

    char new_str[12];
    int new_len = write_int_to_buf(new_str, new_val);

    if (new_len != old_len) {
        int remaining = (int)m->count - pos - old_len;
        if (remaining < 0) return 0;
        memmove(p + new_len, p + old_len, remaining);
        m->count += (new_len - old_len);
    }
    memcpy(p, new_str, new_len);
    return new_len - old_len;
}

static int skip_to_parent_field(const char *s) {
    int pos = 0;
    while (s[pos] >= '0' && s[pos] <= '9') pos++;
    while (s[pos] == ' ') pos++;
    return pos;
}

static void record_id_map(int old_id, int new_id) {
    if (mt_id_state.map_count < MAX_MOUNT_ENTRIES) {
        mt_id_state.map_old[mt_id_state.map_count] = old_id;
        mt_id_state.map_new[mt_id_state.map_count] = new_id;
        mt_id_state.map_count++;
    }
}

static void record_hidden_redirect(int hidden_id, int parent_id) {
    if (mt_id_state.redir_count < MAX_MOUNT_ENTRIES) {
        mt_id_state.redir_hidden[mt_id_state.redir_count] = hidden_id;
        mt_id_state.redir_parent[mt_id_state.redir_count] = parent_id;
        mt_id_state.redir_count++;
    }
}

static int resolve_parent_id(int parent_id) {
    int depth = 0;
    while (depth++ < 20) {
        int found = 0;
        for (int i = 0; i < mt_id_state.redir_count; i++) {
            if (mt_id_state.redir_hidden[i] == parent_id) {
                parent_id = mt_id_state.redir_parent[i];
                found = 1;
                break;
            }
        }
        if (!found) break;
    }
    for (int i = 0; i < mt_id_state.map_count; i++) {
        if (mt_id_state.map_old[i] == parent_id) {
            return mt_id_state.map_new[i];
        }
    }
    return parent_id;
}

static int map_peer_group(int old_group) {
    for (int i = 0; i < mt_id_state.pg_count; i++) {
        if (mt_id_state.pg_old[i] == old_group)
            return mt_id_state.pg_new[i];
    }
    if (mt_id_state.pg_count < MAX_PEER_GROUPS) {
        int idx = mt_id_state.pg_count++;
        mt_id_state.pg_old[idx] = old_group;
        mt_id_state.pg_new[idx] = mt_id_state.pg_next++;
        return mt_id_state.pg_new[idx];
    }
    return old_group;
}

static int skip_n_fields(const char *s, int n) {
    int pos = 0;
    int fields = 0;
    while (fields < n && s[pos]) {
        while (s[pos] == ' ' || s[pos] == '\t') pos++;
        while (s[pos] && s[pos] != ' ' && s[pos] != '\t') pos++;
        fields++;
    }
    return pos;
}

static int count_fields(const char *s, int max_len) {
    int fields = 0;
    int pos = 0;
    while (pos < max_len && s[pos]) {
        while (pos < max_len && (s[pos] == ' ' || s[pos] == '\t')) pos++;
        if (pos >= max_len || s[pos] == '\0') break;
        while (pos < max_len && s[pos] && s[pos] != ' ' && s[pos] != '\t') pos++;
        fields++;
    }
    return fields;
}

static void rewrite_peer_groups(seq_file *m, int line_start, char *line, int line_len) {
    int n_fields = count_fields(line, line_len);
    if (n_fields < 6) return;

    int share_pos = skip_n_fields(line, 3);
    int master_pos = skip_n_fields(line, 4);
    int propagate_from = skip_n_fields(line, n_fields - 3);
    int fs_type_pos = n_fields > 7 ? skip_n_fields(line, n_fields - 2) : -1;

    int share_off = line_start + share_pos;
    int share_val = parse_first_int(line + share_pos);
    if (share_val > 0) {
        int new_share = map_peer_group(share_val);
        if (new_share != share_val) {
            rewrite_int_at(m, share_off, share_val, new_share);
        }
    }

    int master_off = line_start + master_pos;
    int master_val = parse_first_int(line + master_pos);
    if (master_val > 0) {
        int new_master = resolve_parent_id(master_val);
        if (new_master != master_val) {
            rewrite_int_at(m, master_off, master_val, new_master);
        }
    }

    if (propagate_from > 0) {
        int pf_off = line_start + propagate_from;
        int pf_val = parse_first_int(line + propagate_from);
        if (pf_val > 0) {
            int new_pf = resolve_parent_id(pf_val);
            if (new_pf != pf_val) {
                rewrite_int_at(m, pf_off, pf_val, new_pf);
            }
        }
    }

    if (fs_type_pos > 0) {
        int ft_off = line_start + fs_type_pos;
        int ft_val = parse_first_int(line + fs_type_pos);
        if (ft_val > 0) {
            int new_ft = resolve_parent_id(ft_val);
            if (new_ft != ft_val) {
                rewrite_int_at(m, ft_off, ft_val, new_ft);
            }
        }
    }
}

/* ========== show_vfsmnt hooks ========== */

static void show_vfsmnt_before(hook_fargs2_t *args, void *udata) {
    (void)udata;
    seq_file *m = (seq_file *)args->arg0;
    args->local.data0 = m->count;
}

static void show_vfsmnt_after(hook_fargs2_t *args, void *udata) {
    (void)udata;
    if (!is_app_process()) return;

    int start = args->local.data0;
    seq_file *m = (seq_file *)args->arg0;
    int end = m->count;

    char *line = kpm_vmalloc(end - start + 1);
    if (!line) return;
    for (int i = 0; i < end - start; i++)
        line[i] = m->buf[start + i];
    line[end - start] = 0;

    if (should_hide_mount(line)) {
        m->count = start;
    }

    kpm_vfree(line);
}

/* ========== show_mountinfo hooks ========== */

static void show_mountinfo_before(hook_fargs2_t *args, void *udata) {
    (void)udata;
    seq_file *m = (seq_file *)args->arg0;
    args->local.data0 = m->count;
}

static void show_mountinfo_after(hook_fargs2_t *args, void *udata) {
    (void)udata;
    if (!is_app_process()) return;

    int start = args->local.data0;
    seq_file *m = (seq_file *)args->arg0;
    int end = m->count;

    char *line = kpm_vmalloc(end - start + 1);
    if (!line) return;
    for (int i = 0; i < end - start; i++)
        line[i] = m->buf[start + i];
    line[end - start] = 0;

    /* Detect new read session */
    if ((void *)m != mt_id_state.seq) {
        mt_id_state.seq = (void *)m;
        mt_id_state.delta = 0;
        mt_id_state.last_id = 0;
        mt_id_state.map_count = 0;
        mt_id_state.redir_count = 0;
        mt_id_state.pg_count = 0;
        mt_id_state.pg_next = 1;
    }

    int orig_id = parse_first_int(line);
    int parent_field_off = skip_to_parent_field(line);
    int orig_parent_id = parse_first_int(line + parent_field_off);

    if (should_hide_mount(line)) {
        record_hidden_redirect(orig_id, orig_parent_id);
        m->count = start;
    } else {
        rewrite_peer_groups(m, start, line, end - start);

        if (mt_id_state.last_id > 0 && orig_id > mt_id_state.last_id + 1) {
            mt_id_state.delta += (orig_id - mt_id_state.last_id - 1);
        }
        int new_id = orig_id - mt_id_state.delta;
        record_id_map(orig_id, new_id);

        int resolved_parent = resolve_parent_id(orig_parent_id);
        if (resolved_parent != orig_parent_id) {
            int parent_buf_pos = start + parent_field_off;
            rewrite_int_at(m, parent_buf_pos, orig_parent_id, resolved_parent);
        }

        if (mt_id_state.delta > 0) {
            rewrite_int_at(m, start, orig_id, new_id);
        }

        mt_id_state.last_id = orig_id;
    }

    kpm_vfree(line);
}

/* ========== show_vfsstat hooks ========== */

static void show_vfsstat_before(hook_fargs2_t *args, void *udata) {
    (void)udata;
    seq_file *m = (seq_file *)args->arg0;
    args->local.data0 = m->count;
}

static void show_vfsstat_after(hook_fargs2_t *args, void *udata) {
    (void)udata;
    if (!is_app_process()) return;

    int start = args->local.data0;
    seq_file *m = (seq_file *)args->arg0;
    int end = m->count;

    char *line = kpm_vmalloc(end - start + 1);
    if (!line) return;
    for (int i = 0; i < end - start; i++)
        line[i] = m->buf[start + i];
    line[end - start] = 0;

    if (should_hide_mount(line)) {
        m->count = start;
    }

    kpm_vfree(line);
}

/* ========== init / exit ========== */

int shield_mount_init(void) {
    fn_show_vfsmnt = (void *)kallsyms_lookup_name("show_vfsmnt");
    if (fn_show_vfsmnt) {
        hook_wrap2(fn_show_vfsmnt, show_vfsmnt_before, show_vfsmnt_after, NULL);
        pr_info(TAG ": show_vfsmnt hook installed (%p)\n", fn_show_vfsmnt);
    } else {
        pr_info(TAG ": show_vfsmnt not found\n");
    }

    fn_show_mountinfo = (void *)kallsyms_lookup_name("show_mountinfo");
    if (fn_show_mountinfo) {
        hook_wrap2(fn_show_mountinfo, show_mountinfo_before, show_mountinfo_after, NULL);
        pr_info(TAG ": show_mountinfo hook installed (%p)\n", fn_show_mountinfo);
    } else {
        pr_info(TAG ": show_mountinfo not found\n");
    }

    fn_show_vfsstat = (void *)kallsyms_lookup_name("show_vfsstat");
    if (fn_show_vfsstat) {
        hook_wrap2(fn_show_vfsstat, show_vfsstat_before, show_vfsstat_after, NULL);
        pr_info(TAG ": show_vfsstat hook installed (%p)\n", fn_show_vfsstat);
    } else {
        pr_info(TAG ": show_vfsstat not found\n");
    }

    return 0;
}

void shield_mount_exit(void) {
    if (fn_show_vfsmnt) {
        unhook(fn_show_vfsmnt);
        pr_info(TAG ": show_vfsmnt hook removed\n");
    }
    if (fn_show_mountinfo) {
        unhook(fn_show_mountinfo);
        pr_info(TAG ": show_mountinfo hook removed\n");
    }
    if (fn_show_vfsstat) {
        unhook(fn_show_vfsstat);
        pr_info(TAG ": show_vfsstat hook removed\n");
    }
}
