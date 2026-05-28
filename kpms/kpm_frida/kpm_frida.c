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

static int hooks_installed;

static void install_all_hooks(void)
{
    if (hooks_installed)
        return;

    frida_debugger_hide_install();
    frida_maps_hide_install();
    frida_openat_hide_install();
    frida_net_hide_install();
    frida_mem_hide_install();

    hooks_installed = 1;
    pr_info("KPM_FRIDA: all modules installed\n");
}

/*
 * 嵌入模式（开机自启）event 为非空字符串，此时 kallsyms 尚未就绪，
 * 直接 hook 会导致内核死机。延迟到 ctl0 或重新加载时再安装。
 * 手动加载（APatch 界面）event 为 NULL，立即安装。
 */
static long kpm_frida_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("KPM_FRIDA init, event: %s, args: %s\n",
            event ? event : "(null)", args ? args : "(null)");

    if (event && event[0] != '\0') {
        pr_info("KPM_FRIDA: boot stage (%s), deferring hook install\n", event);
        hooks_installed = 0;
        return 0;
    }

    install_all_hooks();
    return 0;
}

/*
 * ctl0: 触发延迟安装（嵌入模式开机后调用），或 echo 测试。
 */
static long kpm_frida_control0(const char *args, char *__user out_msg, int outlen)
{
    static const char prefix[] = "echo: ";
    char echo[64];
    int pos = 0;

    (void)outlen;

    pr_info("KPM_FRIDA control0, args: %s\n", args ? args : "(null)");

    /* 如果 hooks 还没装（嵌入模式延迟），现在安装 */
    if (!hooks_installed) {
        pr_info("KPM_FRIDA: installing hooks via ctl0 trigger\n");
        install_all_hooks();
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

static long kpm_frida_exit(void *__user reserved)
{
    pr_info("KPM_FRIDA exit\n");
    if (hooks_installed) {
        frida_mem_hide_uninstall();
        frida_net_hide_uninstall();
        frida_openat_hide_uninstall();
        frida_maps_hide_uninstall();
        frida_debugger_hide_uninstall();
        hooks_installed = 0;
    }
    pr_info("KPM_FRIDA: all modules uninstalled\n");
    return 0;
}

KPM_INIT(kpm_frida_init);
KPM_CTL0(kpm_frida_control0);
KPM_EXIT(kpm_frida_exit);
