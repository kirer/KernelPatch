/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _SHIELD_CONFIG_H
#define _SHIELD_CONFIG_H

#include <ktypes.h>

/* Maximum pattern counts and string lengths */
#define SHIELD_MAX_PATTERNS  32
#define SHIELD_MAX_PAT_LEN   64
#define SHIELD_ARGS_MAX      2048

/* ========== Runtime configuration ========== */

struct shield_config {
    /* ---- feature toggles (1=enabled, 0=disabled) ---- */
    int feat_maps;
    int feat_apatch;
    int feat_mount;
    int feat_misc;
    int feat_net;
    int feat_debugger;
    int feat_comm;
    int feat_openat;
    int feat_mem;

    /* ---- filter patterns (arrays of strings) ---- */
    int maps_pat_count;
    char maps_pat[SHIELD_MAX_PATTERNS][SHIELD_MAX_PAT_LEN];

    int comm_pat_count;
    char comm_pat[SHIELD_MAX_PATTERNS][SHIELD_MAX_PAT_LEN];

    int tcp_ports_count;
    char tcp_ports[SHIELD_MAX_PATTERNS][SHIELD_MAX_PAT_LEN];

    int tcp_addrs_count;
    char tcp_addrs[SHIELD_MAX_PATTERNS][SHIELD_MAX_PAT_LEN];

    int unix_pat_count;
    char unix_pat[SHIELD_MAX_PATTERNS][SHIELD_MAX_PAT_LEN];

    int block_paths_count;
    char block_paths[SHIELD_MAX_PATTERNS][SHIELD_MAX_PAT_LEN];

    int selinux_from_count;
    char selinux_from[SHIELD_MAX_PATTERNS][SHIELD_MAX_PAT_LEN];
    char selinux_to[SHIELD_MAX_PAT_LEN];

    int mount_pat_count;
    char mount_pat[SHIELD_MAX_PATTERNS][SHIELD_MAX_PAT_LEN];

    int dent_pat_count;
    char dent_pat[SHIELD_MAX_PATTERNS][SHIELD_MAX_PAT_LEN];

    int readlink_pat_count;
    char readlink_pat[SHIELD_MAX_PATTERNS][SHIELD_MAX_PAT_LEN];
};

/* Global config instance */
extern struct shield_config g_config;

/* ========== config API ========== */

/* Parse args string into g_config. Returns 0 on success. */
int shield_config_parse(const char *args);

/* Set all features and patterns to built-in defaults. */
void shield_config_set_defaults(void);

/* Check if a string matches any pattern in a pattern array (substring match). */
int shield_pattern_match(const char *str, char patterns[][SHIELD_MAX_PAT_LEN], int count);

#endif /* _SHIELD_CONFIG_H */
