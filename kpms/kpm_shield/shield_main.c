/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * shield_main.c - KPM_SHIELD main entry point.
 *
 * Unified module merging kpm_hide + kpm_frida with fine-grained
 * parameter control via args string.
 *
 * Parameter format: key=val1;val2;...,key2=1,...
 *
 * Feature toggles (1=enabled, 0=disabled):
 *   maps, apatch, mount, misc, net, debugger, comm, openat, mem
 *
 * Configurable patterns:
 *   maps_pat, comm_pat, tcp_ports, tcp_addrs, unix_pat,
 *   block_paths, selinux_from, selinux_to, mount_pat,
 *   dent_pat, readlink_pat
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <linux/printk.h>

#include "shield_config.h"
#include "shield_utils.h"
#include "shield_maps.h"
#include "shield_apatch.h"
#include "shield_mount.h"
#include "shield_misc.h"
#include "shield_net.h"
#include "shield_debugger.h"
#include "shield_openat.h"
#include "shield_mem.h"

KPM_NAME("KPM_SHIELD");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KernelPatch");
KPM_DESCRIPTION("KPM_SHIELD: unified hide & frida shielding with configurable parameters");

#define TAG "KPM_SHIELD"

static int g_installed = 0;

/* ========== install all enabled hooks ========== */

static int install_hooks(void) {
    int rc;

    if (g_installed) return 0;

    /* Shared utilities */
    rc = shield_utils_init();
    if (rc < 0) {
        pr_info(TAG ": shield_utils_init failed (%d)\n", rc);
        return rc;
    }

    if (g_config.feat_maps) {
        rc = shield_maps_init();
        if (rc < 0) {
            pr_info(TAG ": shield_maps_init failed (%d)\n", rc);
        } else {
            pr_info(TAG ": maps OK\n");
        }
    }

    if (g_config.feat_apatch) {
        rc = shield_apatch_init();
        if (rc < 0) {
            pr_info(TAG ": shield_apatch_init failed (%d)\n", rc);
        } else {
            pr_info(TAG ": apatch OK\n");
        }
    }

    if (g_config.feat_mount) {
        rc = shield_mount_init();
        if (rc < 0) {
            pr_info(TAG ": shield_mount_init failed (%d)\n", rc);
        } else {
            pr_info(TAG ": mount OK\n");
        }
    }

    if (g_config.feat_misc) {
        rc = shield_misc_init();
        if (rc < 0) {
            pr_info(TAG ": shield_misc_init failed (%d)\n", rc);
        } else {
            pr_info(TAG ": misc OK\n");
        }
    }

    if (g_config.feat_net) {
        rc = shield_net_init();
        if (rc < 0) {
            pr_info(TAG ": shield_net_init failed (%d)\n", rc);
        } else {
            pr_info(TAG ": net OK\n");
        }
    }

    if (g_config.feat_debugger) {
        rc = shield_debugger_init();
        if (rc < 0) {
            pr_info(TAG ": shield_debugger_init failed (%d)\n", rc);
        } else {
            pr_info(TAG ": debugger OK\n");
        }
    }

    if (g_config.feat_openat) {
        rc = shield_openat_init();
        if (rc < 0) {
            pr_info(TAG ": shield_openat_init failed (%d)\n", rc);
        } else {
            pr_info(TAG ": openat OK\n");
        }
    }

    if (g_config.feat_mem) {
        rc = shield_mem_init();
        if (rc < 0) {
            pr_info(TAG ": shield_mem_init failed (%d)\n", rc);
        } else {
            pr_info(TAG ": mem OK\n");
        }
    }

    g_installed = 1;
    pr_info(TAG ": all enabled modules installed\n");
    return 0;
}

/* ========== uninstall hooks ========== */

static void uninstall_hooks(void) {
    if (!g_installed) return;

    shield_mem_exit();
    shield_openat_exit();
    shield_debugger_exit();
    shield_net_exit();
    shield_misc_exit();
    shield_mount_exit();
    shield_apatch_exit();
    shield_maps_exit();

    g_installed = 0;
    pr_info(TAG ": all modules uninstalled\n");
}

/* ========== KPM entry points ========== */

/*
 * Uses kallsyms_lookup_name("printk") to detect if the kernel symbol
 * subsystem is ready, rather than relying on the ''event'' parameter.
 * If kallsyms is ready, install hooks immediately regardless of event.
 * If kallsyms is not ready (boot stage), defer to ctl0.
 */
static long shield_init(const char *args, const char *event, void *__user reserved) {
    pr_info(TAG ": init, event: %s, args: %s\n",
            event ? event : "(null)", args ? args : "(null)");

    if (!kallsyms_lookup_name("printk")) {
        /* Boot stage: kallsyms not ready, set defaults and defer */
        shield_config_set_defaults();
        pr_info(TAG ": boot stage (%s), deferring hook install\n", event);
        g_installed = 0;
        return 0;
    }

    /* kallsyms ready: parse args and install immediately */
    shield_config_parse(args);
    return install_hooks();
}

/*
 * ctl0: trigger deferred install (embed mode), or runtime reconfiguration.
 */
static long shield_control0(const char *args, char *__user out_msg, int outlen) {
    static const char prefix[] = "KPM_SHIELD: ";
    char echo[64];
    int pos = 0;

    (void)outlen;

    pr_info(TAG ": control0, args: %s\n", args ? args : "(null)");

    if (!g_installed) {
        /* Deferred install: parse config first, then install hooks */
        shield_config_parse(args);
        pr_info(TAG ": installing hooks via ctl0 trigger\n");
        install_hooks();
    } else if (args && args[0] != '\0') {
        /* Runtime reconfiguration of already-installed module */
        shield_config_parse(args);
        pr_info(TAG ": runtime reconfig applied\n");
    }

    for (int i = 0; i < (int)(sizeof(prefix) - 1) && pos < (int)(sizeof(echo) - 1); ++i)
        echo[pos++] = prefix[i];

    if (args) {
        for (int i = 0; args[i] != '\0' && pos < (int)(sizeof(echo) - 1); ++i)
            echo[pos++] = args[i];
    }

    echo[pos] = '\0';
    compat_copy_to_user(out_msg, echo, pos + 1);
    return 0;
}

static long shield_exit(void *__user reserved) {
    pr_info(TAG ": exit\n");
    uninstall_hooks();
    return 0;
}

KPM_INIT(shield_init);
KPM_CTL0(shield_control0);
KPM_EXIT(shield_exit);
