/*
 * ⚠️⚠️⚠️  警告：此模块会导致手机死机，请勿编译到 KPM_FRIDA 中！ ⚠️⚠️⚠️
 *
 * prctl_hide.c - hook prctl(PR_GET_NAME) to disguise frida thread names
 *
 * 实测问题（Xiaomi 2201123C, Android 13, Kernel 5.10.101）：
 *   - 加载此 hook 后手机直接卡死，需要强制重启
 *   - 原因：prctl 是高频系统调用，内核 hook 的回调路径在 PAN (Privileged
 *     Access Never) 内核上存在竞态/死锁风险
 *   - 即使 hook 只在 option==16 时处理 after 回调，仍有概率触发内核 panic
 *
 * 替代方案：
 *   - frida_hide.c 已 hook __get_task_comm，这是 prctl(PR_GET_NAME)
 *     在内核侧的底层实现，效果等价且不会导致死机
 *   - __get_task_comm 调用频率远低于 prctl，在 seq_file 路径中使用，
 *     不涉及用户态内存操作，更安全
 *
 * 此文件保留仅供参考，请勿在 kpm_frida.c 中 include 或调用。
 */

#include "prctl_hide.h"

#include <hook.h>
#include <kputils.h>
#include <syscall.h>

#include <linux/printk.h>
#include <linux/string.h>

/* arm64 __NR_prctl = 167, 5 arguments */
#define PRCTL_NR     167
#define PR_GET_NAME   16

static int hook_prctl_status = 0;

static int is_frida_thread_name(const char *name)
{
    if (!name || name[0] == '\0')
        return 0;

    if (strstr(name, "frida"))
        return 1;
    if (strstr(name, "gum-js-loop"))
        return 1;
    if (strstr(name, "gmain"))
        return 1;
    if (strstr(name, "gdbus"))
        return 1;
    if (strstr(name, "linjector"))
        return 1;
    if (strstr(name, "pool-spawner"))
        return 1;

    return 0;
}

static void after_prctl(hook_fargs5_t *args, void *udata)
{
    char name[16];
    long len;
    char __user *buf;
    int option;

    (void)udata;

    option = (int)syscall_argn(args, 0);
    if (option != PR_GET_NAME)
        return;

    if (args->ret != 0)
        return;

    buf = (char __user *)syscall_argn(args, 1);
    if (!buf)
        return;

    len = compat_strncpy_from_user(name, buf, sizeof(name));
    if (len <= 0)
        return;

    name[sizeof(name) - 1] = '\0';

    if (!is_frida_thread_name(name))
        return;

    compat_copy_to_user(buf, "binder", 7);
}

void frida_prctl_hide_install(void)
{
    hook_err_t err;

    err = fp_hook_syscalln(PRCTL_NR, 5, NULL, after_prctl, NULL);
    if (err) {
        pr_err("KPM_FRIDA: hook prctl failed %d\n", err);
    } else {
        hook_prctl_status = 1;
        pr_info("KPM_FRIDA: prctl PR_GET_NAME filter installed\n");
    }
}

void frida_prctl_hide_uninstall(void)
{
    if (hook_prctl_status) {
        fp_unhook_syscalln(PRCTL_NR, NULL, after_prctl);
        hook_prctl_status = 0;
    }
    pr_info("KPM_FRIDA: prctl hide uninstalled\n");
}
