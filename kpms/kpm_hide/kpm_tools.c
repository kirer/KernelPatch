/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_tools.c - KernelPatch module main entry.
 *
 * Orchestrates sub-modules:
 *   - hide_maps:   hide injection artifacts from /proc/pid/maps & smaps
 *   - hide_apatch: bypass APatch syscall hooks for excluded processes
 *   - hide_mount:  hide APatch/zygisk mount points
 *   - hide_misc:   hide SELinux labels, directory entries, readlink paths
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <linux/printk.h>

#include "kpm_utils.h"
#include "hide_maps.h"
#include "hide_apatch.h"
#include "hide_mount.h"
#include "hide_misc.h"
#include "hide_net.h"

KPM_NAME("KPM_HIDE");
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KernelPatch");
KPM_DESCRIPTION("KernelPatch hiding toolkit");

#define TAG "KPM_HIDE"

static long kpm_tools_init(const char *args, const char *event, void *__user reserved) {
    int rc;
    pr_info(TAG ": init\n");

    /* Shared utilities (vmalloc/vfree, etc.) */
    rc = kpm_utils_init();
    if (rc < 0) {
        pr_info(TAG ": kpm_utils_init failed (%d)\n", rc);
        return rc;
    }

    /* Maps hiding for injection artifacts */
    rc = hide_maps_init();
    if (rc < 0) {
        pr_info(TAG ": hide_maps_init failed (%d)\n", rc);
        /* non-fatal, continue with other modules */
    } else {
        pr_info(TAG ": hide_maps OK\n");
    }

    /* APatch syscall table bypass */
    rc = hide_apatch_init();
    if (rc < 0) {
        pr_info(TAG ": hide_apatch_init failed (%d)\n", rc);
    } else {
        pr_info(TAG ": hide_apatch OK\n");
    }

    /* Mount point hiding */
    rc = hide_mount_init();
    if (rc < 0) {
        pr_info(TAG ": hide_mount_init failed (%d)\n", rc);
    } else {
        pr_info(TAG ": hide_mount OK\n");
    }

    /* Misc: SELinux, getdents64, readlink */
    rc = hide_misc_init();
    if (rc < 0) {
        pr_info(TAG ": hide_misc_init failed (%d)\n", rc);
    } else {
        pr_info(TAG ": hide_misc OK\n");
    }

    /* Net: /proc/net/tcp, /proc/net/unix */
    rc = hide_net_init();
    if (rc < 0) {
        pr_info(TAG ": hide_net_init failed (%d)\n", rc);
    } else {
        pr_info(TAG ": hide_net OK\n");
    }

    pr_info(TAG ": ready\n");
    return 0;
}

static long kpm_tools_exit(void *__user reserved) {
    pr_info(TAG ": exit\n");

    hide_net_exit();
    hide_misc_exit();
    hide_mount_exit();
    hide_apatch_exit();
    hide_maps_exit();

    pr_info(TAG ": all modules unloaded\n");
    return 0;
}

static long kpm_tools_ctl0(const char *args, char *__user out_msg, int outlen) {
    pr_info(TAG ": ctl0 args=%s\n", args);
    return 0;
}

KPM_INIT(kpm_tools_init);
KPM_CTL0(kpm_tools_ctl0);
KPM_EXIT(kpm_tools_exit);
