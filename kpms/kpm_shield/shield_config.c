/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * shield_config.c - Runtime configuration parsing and pattern matching.
 */

#include "shield_config.h"

#include <linux/printk.h>
#include <linux/string.h>

#define TAG "KPM_SHIELD/cfg"

struct shield_config g_config;

/* ========== default patterns ========== */

static const char *default_maps_pat[] = {
    "memfd:wwb", "[anon:wwb]",
    "frida", "gadget", "linjector", "gmain",
};
static const int default_maps_pat_count = 6;

static const char *default_comm_pat[] = {
    "gum-js-loop", "pool-frida", "pool-spawner",
    "linjector", "gmain", "gdbus", "frida",
};
static const int default_comm_pat_count = 7;

static const char *default_tcp_ports[] = {
    "31A4", "69A2", "69A3",
};
static const int default_tcp_ports_count = 3;

static const char *default_tcp_addrs[] = {
    "0100007F",
};
static const int default_tcp_addrs_count = 1;

static const char *default_unix_pat[] = {
    "wwb",
};
static const int default_unix_pat_count = 1;

static const char *default_block_paths[] = {
    "re.frida.server", "frida-agent-32.so", "frida-agent-64.so",
    "frida-agent.so", "frida-gadget", "linjector",
};
static const int default_block_paths_count = 6;

static const char *default_selinux_from[] = {
    "u:r:magisk:s0", "u:r:su:s0",
};
static const int default_selinux_from_count = 2;

static const char *default_mount_pat[] = {
    "APatch", "revanced", "zygisk", "dex2oat",
    "/data/adb/modules", "/debug_ramdisk",
};
static const int default_mount_pat_count = 6;

static const char *default_dent_pat[] = {
    "debug_ramdisk",
};
static const int default_dent_pat_count = 1;

static const char *default_readlink_pat[] = {
    "zygisk_gadget", "zygisk_lsposed", "memfd:wwb",
};
static const int default_readlink_pat_count = 3;

/* ========== helpers ========== */

static void copy_patterns(char dest[][SHIELD_MAX_PAT_LEN], int *dest_count,
                          const char *src[], int src_count) {
    int n = src_count;
    if (n > SHIELD_MAX_PATTERNS) n = SHIELD_MAX_PATTERNS;
    for (int i = 0; i < n; i++) {
        int len = strlen(src[i]);
        if (len >= SHIELD_MAX_PAT_LEN) len = SHIELD_MAX_PAT_LEN - 1;
        memcpy(dest[i], src[i], len);
        dest[i][len] = '\0';
    }
    *dest_count = n;
}

void shield_config_set_defaults(void) {
    /* Features: all enabled by default */
    g_config.feat_maps     = 1;
    g_config.feat_apatch   = 1;
    g_config.feat_mount    = 1;
    g_config.feat_misc     = 1;
    g_config.feat_net      = 1;
    g_config.feat_debugger = 1;
    g_config.feat_comm     = 1;
    g_config.feat_openat   = 1;
    g_config.feat_mem      = 1;

    /* Patterns */
    copy_patterns(g_config.maps_pat,   &g_config.maps_pat_count,   default_maps_pat,   default_maps_pat_count);
    copy_patterns(g_config.comm_pat,   &g_config.comm_pat_count,   default_comm_pat,   default_comm_pat_count);
    copy_patterns(g_config.tcp_ports,  &g_config.tcp_ports_count,  default_tcp_ports,  default_tcp_ports_count);
    copy_patterns(g_config.tcp_addrs,  &g_config.tcp_addrs_count,  default_tcp_addrs,  default_tcp_addrs_count);
    copy_patterns(g_config.unix_pat,   &g_config.unix_pat_count,   default_unix_pat,   default_unix_pat_count);
    copy_patterns(g_config.block_paths,&g_config.block_paths_count,default_block_paths,default_block_paths_count);
    copy_patterns(g_config.selinux_from,&g_config.selinux_from_count,default_selinux_from,default_selinux_from_count);

    /* selinux_to (single value) */
    {
        const char *s = "u:r:surfaceflinger:s0";
        int len = strlen(s);
        if (len >= SHIELD_MAX_PAT_LEN) len = SHIELD_MAX_PAT_LEN - 1;
        memcpy(g_config.selinux_to, s, len);
        g_config.selinux_to[len] = '\0';
    }

    copy_patterns(g_config.mount_pat,    &g_config.mount_pat_count,    default_mount_pat,    default_mount_pat_count);
    copy_patterns(g_config.dent_pat,     &g_config.dent_pat_count,     default_dent_pat,     default_dent_pat_count);
    copy_patterns(g_config.readlink_pat, &g_config.readlink_pat_count, default_readlink_pat, default_readlink_pat_count);
}

/* ========== args parsing ========== */

/*
 * Parse a single key=value pair.
 * key: "feat_maps", "tcp_ports", etc.
 * value: "1", "0", or "31A4;69A2;69A3" (semicolon-separated)
 */
static int parse_one_kv(char *token) {
    char *eq = strchr(token, '=');
    if (!eq) {
        /* bare key like "maps" (enable without =1) */
        /* We only support key=value format; ignore bare tokens */
        pr_info(TAG ": ignoring token without '=': %s\n", token);
        return 0;
    }

    /* Split into key and value */
    *eq = '\0';
    char *key = token;
    char *val = eq + 1;

    /* Trim leading/trailing whitespace */
    while (*key == ' ' || *key == '\t') key++;

    /* ---- feature toggles ---- */
    if (strcmp(key, "maps") == 0) {
        g_config.feat_maps = (val[0] != '0');
    } else if (strcmp(key, "apatch") == 0) {
        g_config.feat_apatch = (val[0] != '0');
    } else if (strcmp(key, "mount") == 0) {
        g_config.feat_mount = (val[0] != '0');
    } else if (strcmp(key, "misc") == 0) {
        g_config.feat_misc = (val[0] != '0');
    } else if (strcmp(key, "net") == 0) {
        g_config.feat_net = (val[0] != '0');
    } else if (strcmp(key, "debugger") == 0) {
        g_config.feat_debugger = (val[0] != '0');
    } else if (strcmp(key, "comm") == 0) {
        g_config.feat_comm = (val[0] != '0');
    } else if (strcmp(key, "openat") == 0) {
        g_config.feat_openat = (val[0] != '0');
    } else if (strcmp(key, "mem") == 0) {
        g_config.feat_mem = (val[0] != '0');

    /* ---- pattern arrays ---- */
    } else if (strcmp(key, "maps_pat") == 0) {
        g_config.maps_pat_count = 0;
        char *p = val;
        while (p && *p && g_config.maps_pat_count < SHIELD_MAX_PATTERNS) {
            char *semi = strchr(p, ';');
            if (semi) *semi = '\0';
            int len = strlen(p);
            if (len >= SHIELD_MAX_PAT_LEN) len = SHIELD_MAX_PAT_LEN - 1;
            memcpy(g_config.maps_pat[g_config.maps_pat_count], p, len);
            g_config.maps_pat[g_config.maps_pat_count][len] = '\0';
            g_config.maps_pat_count++;
            p = semi ? semi + 1 : NULL;
        }
    } else if (strcmp(key, "comm_pat") == 0) {
        g_config.comm_pat_count = 0;
        char *p = val;
        while (p && *p && g_config.comm_pat_count < SHIELD_MAX_PATTERNS) {
            char *semi = strchr(p, ';');
            if (semi) *semi = '\0';
            int len = strlen(p);
            if (len >= SHIELD_MAX_PAT_LEN) len = SHIELD_MAX_PAT_LEN - 1;
            memcpy(g_config.comm_pat[g_config.comm_pat_count], p, len);
            g_config.comm_pat[g_config.comm_pat_count][len] = '\0';
            g_config.comm_pat_count++;
            p = semi ? semi + 1 : NULL;
        }
    } else if (strcmp(key, "tcp_ports") == 0) {
        g_config.tcp_ports_count = 0;
        char *p = val;
        while (p && *p && g_config.tcp_ports_count < SHIELD_MAX_PATTERNS) {
            char *semi = strchr(p, ';');
            if (semi) *semi = '\0';
            int len = strlen(p);
            if (len >= SHIELD_MAX_PAT_LEN) len = SHIELD_MAX_PAT_LEN - 1;
            memcpy(g_config.tcp_ports[g_config.tcp_ports_count], p, len);
            g_config.tcp_ports[g_config.tcp_ports_count][len] = '\0';
            g_config.tcp_ports_count++;
            p = semi ? semi + 1 : NULL;
        }
    } else if (strcmp(key, "tcp_addrs") == 0) {
        g_config.tcp_addrs_count = 0;
        char *p = val;
        while (p && *p && g_config.tcp_addrs_count < SHIELD_MAX_PATTERNS) {
            char *semi = strchr(p, ';');
            if (semi) *semi = '\0';
            int len = strlen(p);
            if (len >= SHIELD_MAX_PAT_LEN) len = SHIELD_MAX_PAT_LEN - 1;
            memcpy(g_config.tcp_addrs[g_config.tcp_addrs_count], p, len);
            g_config.tcp_addrs[g_config.tcp_addrs_count][len] = '\0';
            g_config.tcp_addrs_count++;
            p = semi ? semi + 1 : NULL;
        }
    } else if (strcmp(key, "unix_pat") == 0) {
        g_config.unix_pat_count = 0;
        char *p = val;
        while (p && *p && g_config.unix_pat_count < SHIELD_MAX_PATTERNS) {
            char *semi = strchr(p, ';');
            if (semi) *semi = '\0';
            int len = strlen(p);
            if (len >= SHIELD_MAX_PAT_LEN) len = SHIELD_MAX_PAT_LEN - 1;
            memcpy(g_config.unix_pat[g_config.unix_pat_count], p, len);
            g_config.unix_pat[g_config.unix_pat_count][len] = '\0';
            g_config.unix_pat_count++;
            p = semi ? semi + 1 : NULL;
        }
    } else if (strcmp(key, "block_paths") == 0) {
        g_config.block_paths_count = 0;
        char *p = val;
        while (p && *p && g_config.block_paths_count < SHIELD_MAX_PATTERNS) {
            char *semi = strchr(p, ';');
            if (semi) *semi = '\0';
            int len = strlen(p);
            if (len >= SHIELD_MAX_PAT_LEN) len = SHIELD_MAX_PAT_LEN - 1;
            memcpy(g_config.block_paths[g_config.block_paths_count], p, len);
            g_config.block_paths[g_config.block_paths_count][len] = '\0';
            g_config.block_paths_count++;
            p = semi ? semi + 1 : NULL;
        }
    } else if (strcmp(key, "selinux_from") == 0) {
        g_config.selinux_from_count = 0;
        char *p = val;
        while (p && *p && g_config.selinux_from_count < SHIELD_MAX_PATTERNS) {
            char *semi = strchr(p, ';');
            if (semi) *semi = '\0';
            int len = strlen(p);
            if (len >= SHIELD_MAX_PAT_LEN) len = SHIELD_MAX_PAT_LEN - 1;
            memcpy(g_config.selinux_from[g_config.selinux_from_count], p, len);
            g_config.selinux_from[g_config.selinux_from_count][len] = '\0';
            g_config.selinux_from_count++;
            p = semi ? semi + 1 : NULL;
        }
    } else if (strcmp(key, "selinux_to") == 0) {
        int len = strlen(val);
        if (len >= SHIELD_MAX_PAT_LEN) len = SHIELD_MAX_PAT_LEN - 1;
        memcpy(g_config.selinux_to, val, len);
        g_config.selinux_to[len] = '\0';
    } else if (strcmp(key, "mount_pat") == 0) {
        g_config.mount_pat_count = 0;
        char *p = val;
        while (p && *p && g_config.mount_pat_count < SHIELD_MAX_PATTERNS) {
            char *semi = strchr(p, ';');
            if (semi) *semi = '\0';
            int len = strlen(p);
            if (len >= SHIELD_MAX_PAT_LEN) len = SHIELD_MAX_PAT_LEN - 1;
            memcpy(g_config.mount_pat[g_config.mount_pat_count], p, len);
            g_config.mount_pat[g_config.mount_pat_count][len] = '\0';
            g_config.mount_pat_count++;
            p = semi ? semi + 1 : NULL;
        }
    } else if (strcmp(key, "dent_pat") == 0) {
        g_config.dent_pat_count = 0;
        char *p = val;
        while (p && *p && g_config.dent_pat_count < SHIELD_MAX_PATTERNS) {
            char *semi = strchr(p, ';');
            if (semi) *semi = '\0';
            int len = strlen(p);
            if (len >= SHIELD_MAX_PAT_LEN) len = SHIELD_MAX_PAT_LEN - 1;
            memcpy(g_config.dent_pat[g_config.dent_pat_count], p, len);
            g_config.dent_pat[g_config.dent_pat_count][len] = '\0';
            g_config.dent_pat_count++;
            p = semi ? semi + 1 : NULL;
        }
    } else if (strcmp(key, "readlink_pat") == 0) {
        g_config.readlink_pat_count = 0;
        char *p = val;
        while (p && *p && g_config.readlink_pat_count < SHIELD_MAX_PATTERNS) {
            char *semi = strchr(p, ';');
            if (semi) *semi = '\0';
            int len = strlen(p);
            if (len >= SHIELD_MAX_PAT_LEN) len = SHIELD_MAX_PAT_LEN - 1;
            memcpy(g_config.readlink_pat[g_config.readlink_pat_count], p, len);
            g_config.readlink_pat[g_config.readlink_pat_count][len] = '\0';
            g_config.readlink_pat_count++;
            p = semi ? semi + 1 : NULL;
        }
    } else {
        pr_info(TAG ": unknown config key: %s\n", key);
    }

    return 0;
}

int shield_config_parse(const char *args) {
    /* Start with defaults, then override */
    shield_config_set_defaults();

    if (!args || args[0] == '\0') {
        pr_info(TAG ": no args, using defaults (all features on)\n");
        return 0;
    }

    /* Copy to writable buffer since strtok modifies */
    char buf[SHIELD_ARGS_MAX];
    int arglen = strlen(args);
    if (arglen >= SHIELD_ARGS_MAX) arglen = SHIELD_ARGS_MAX - 1;
    memcpy(buf, args, arglen);
    buf[arglen] = '\0';

    /* Split by comma */
    char *saveptr;
    char *token = buf;
    while (token && *token) {
        /* Find next comma or end */
        char *comma = strchr(token, ',');
        if (comma) *comma = '\0';

        parse_one_kv(token);

        token = comma ? comma + 1 : NULL;
    }

    pr_info(TAG ": parsed config: maps=%d apatch=%d mount=%d misc=%d net=%d debugger=%d comm=%d openat=%d mem=%d\n",
            g_config.feat_maps, g_config.feat_apatch, g_config.feat_mount, g_config.feat_misc,
            g_config.feat_net, g_config.feat_debugger, g_config.feat_comm, g_config.feat_openat, g_config.feat_mem);

    return 0;
}

/* ========== pattern matching ========== */

int shield_pattern_match(const char *str, char patterns[][SHIELD_MAX_PAT_LEN], int count) {
    if (!str || count <= 0) return 0;
    for (int i = 0; i < count; i++) {
        if (patterns[i][0] != '\0' && strstr(str, patterns[i]))
            return 1;
    }
    return 0;
}
