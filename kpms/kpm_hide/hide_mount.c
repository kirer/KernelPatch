/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * hide_mount.c - Hide APatch/zygisk mount points from /proc/mounts,
 *                /proc/self/mountinfo, and /proc/self/mountstats.
 *
 * Uses hook_wrap2 on show_vfsmnt, show_mountinfo, show_vfsstat.
 * For mountinfo, performs mount ID / parent ID / peer group rewriting
 * to eliminate gaps left by hidden entries.
 *
 * Ported from xiaojia-hide/src/hide_proc.c.
 */

#include <compiler.h>
#include <hook.h>
#include <kputils.h>
#include <ksyms.h>
#include <ktypes.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <stdbool.h>

#include "hide_maps.h"   /* seq_file, seq_operations */
#include "kpm_utils.h"

#define TAG "KPM_HIDE/mount"

/* ========== mount ID rewriting state ========== */

#define MAX_PEER_GROUPS  256
#define MAX_MOUNT_ENTRIES 512

static struct {
    void *seq;       /* current seq_file pointer, detect new read session */
    int last_id;     /* last processed original mount ID */
    int delta;       /* accumulated gap (amount to subtract) */

    /* mount ID mapping: old_id -> new_id */
    int map_old[MAX_MOUNT_ENTRIES];
    int map_new[MAX_MOUNT_ENTRIES];
    int map_count;

    /* hidden mount redirect: hidden_id -> parent_id */
    int redir_hidden[MAX_MOUNT_ENTRIES];
    int redir_parent[MAX_MOUNT_ENTRIES];
    int redir_count;

    /* peer group remapping */
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
    if (strstr(line, "APatch") || strstr(line, "revanced") ||
        strstr(line, "zygisk") || strstr(line, "dex2oat") ||
        strstr(line, "/data/adb/modules") || strstr(line, "/debug_ramdisk")) {
        return true;
    }
    return false;
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

struct pg_entry {
    int buf_offset;
    int old_val;
};

static char *safe_strstr(const char *haystack, int haystack_len, const char *needle, int needle_len) {
    if (haystack_len < needle_len) return NULL;
    for (int i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0)
            return (char *)(haystack + i);
    }
    return NULL;
}

static void rewrite_peer_groups(seq_file *m, int start, const char *line, int line_len) {
    const char *prefixes[] = {"shared:", "master:", "propagate_from:"};
    int prefix_lens[] = {7, 7, 15};
    struct pg_entry entries[8];
    int entry_count = 0;

    for (int pi = 0; pi < 3; pi++) {
        const char *search_start = line;
        int remaining = line_len;
        while (remaining > 0) {
            char *found = safe_strstr(search_start, remaining, prefixes[pi], prefix_lens[pi]);
            if (!found) break;

            const char *num_start = found + prefix_lens[pi];
            int num_offset_in_line = num_start - line;
            if (num_offset_in_line >= line_len) break;

            int val = parse_first_int(num_start);
            if (val > 0 && entry_count < 8) {
                entries[entry_count].buf_offset = start + num_offset_in_line;
                entries[entry_count].old_val = val;
                entry_count++;
            }

            int advance = (found - search_start) + prefix_lens[pi] + 1;
            search_start += advance;
            remaining -= advance;
        }
    }

    if (entry_count == 0) return;

    /* Sort by buf_offset descending (rewrite from back to front) */
    for (int i = 0; i < entry_count - 1; i++) {
        for (int j = i + 1; j < entry_count; j++) {
            if (entries[j].buf_offset > entries[i].buf_offset) {
                struct pg_entry tmp = entries[i];
                entries[i] = entries[j];
                entries[j] = tmp;
            }
        }
    }

    for (int i = 0; i < entry_count; i++) {
        int new_val = map_peer_group(entries[i].old_val);
        if (new_val != entries[i].old_val) {
            rewrite_int_at(m, entries[i].buf_offset, entries[i].old_val, new_val);
        }
    }
}

/* ========== show_vfsmnt hooks (/proc/mounts) ========== */

static void show_vfsmnt_before(hook_fargs2_t *args, void *udata) {
    seq_file *m = (seq_file *)args->arg0;
    args->local.data0 = m->count;
}

static void show_vfsmnt_after(hook_fargs2_t *args, void *udata) {
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

/* ========== show_mountinfo hooks (/proc/self/mountinfo) ========== */

static void show_mountinfo_before(hook_fargs2_t *args, void *udata) {
    seq_file *m = (seq_file *)args->arg0;
    args->local.data0 = m->count;
}

static void show_mountinfo_after(hook_fargs2_t *args, void *udata) {
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
        /* Rewrite peer groups (rightmost fields, won't shift earlier offsets) */
        rewrite_peer_groups(m, start, line, end - start);

        /* Compute new mount_id */
        if (mt_id_state.last_id > 0 && orig_id > mt_id_state.last_id + 1) {
            mt_id_state.delta += (orig_id - mt_id_state.last_id - 1);
        }
        int new_id = orig_id - mt_id_state.delta;

        record_id_map(orig_id, new_id);

        /* Rewrite parent_id */
        int resolved_parent = resolve_parent_id(orig_parent_id);
        if (resolved_parent != orig_parent_id) {
            int parent_buf_pos = start + parent_field_off;
            rewrite_int_at(m, parent_buf_pos, orig_parent_id, resolved_parent);
        }

        /* Rewrite mount_id (leftmost, do last) */
        if (mt_id_state.delta > 0) {
            rewrite_int_at(m, start, orig_id, new_id);
        }

        mt_id_state.last_id = orig_id;
    }

    kpm_vfree(line);
}

/* ========== show_vfsstat hooks (/proc/self/mountstats) ========== */

static void show_vfsstat_before(hook_fargs2_t *args, void *udata) {
    seq_file *m = (seq_file *)args->arg0;
    args->local.data0 = m->count;
}

static void show_vfsstat_after(hook_fargs2_t *args, void *udata) {
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

int hide_mount_init(void) {
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

void hide_mount_exit(void) {
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
