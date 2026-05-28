#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <kputils.h>
#include <linux/string.h>

#include "debugger_hide.h"
#include "frida_hide.h"
#include "openat_hide.h"
#include "net_hide.h"
#include "mem_hide.h"

KPM_NAME("KPM_FRIDA");
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("pandaos");
KPM_DESCRIPTION("KPM_FRIDA: comprehensive frida & debugger hiding.");

static long kpm_frida_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("KPM_FRIDA init, event: %s, args: %s\n", event, args);

    frida_debugger_hide_install();
    frida_maps_hide_install();
    frida_openat_hide_install();
    frida_net_hide_install();
    frida_mem_hide_install();

    pr_info("KPM_FRIDA: all modules installed\n");
    return 0;
}

static long kpm_frida_control0(const char *args, char *__user out_msg, int outlen)
{
    static const char prefix[] = "echo: ";
    char echo[64];
    int pos = 0;

    (void)outlen;

    pr_info("KPM_FRIDA control0, args: %s\n", args);

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

static long kpm_frida_exit(void *__user reserved)
{
    pr_info("KPM_FRIDA exit\n");
    frida_mem_hide_uninstall();
    frida_net_hide_uninstall();
    frida_openat_hide_uninstall();
    frida_maps_hide_uninstall();
    frida_debugger_hide_uninstall();
    pr_info("KPM_FRIDA: all modules uninstalled\n");
    return 0;
}

KPM_INIT(kpm_frida_init);
KPM_CTL0(kpm_frida_control0);
KPM_EXIT(kpm_frida_exit);
