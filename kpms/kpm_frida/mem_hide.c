#include "mem_hide.h"

#include "common.h"
#include <hook.h>
#include <linux/kallsyms.h>
#include <linux/printk.h>
#include <linux/string.h>

static void *access_remote_vm_fn = 0;

#define FOLL_WRITE 0x01

static const char *mem_sigs[] = {
    "LIBFRIDA",
    "frida-agent",
    "frida-gadget",
    "frida_agent",
    "frida-server",
    "re.frida.server",
    "frida:rpc",
    "gum-js-loop",
    "GumScript",
    "linjector",
};

#define NUM_SIGS (sizeof(mem_sigs) / sizeof(mem_sigs[0]))

static void __attribute__((optimize("O0"))) zero_bytes(volatile char *buf, int len)
{
    for (int i = 0; i < len; ++i)
        buf[i] = 0;
}

static void scrub_frida_signatures(char *buf, int len)
{
    for (int s = 0; s < (int)NUM_SIGS; s++) {
        const char *sig = mem_sigs[s];
        int sig_len = (int)strlen(sig);

        if (sig_len > len)
            continue;

        for (int i = 0; i <= len - sig_len; i++) {
            if (memcmp(buf + i, sig, sig_len) == 0) {
                zero_bytes((volatile char *)(buf + i), sig_len);
                i += sig_len - 1;
            }
        }
    }
}

static void after_access_remote_vm(hook_fargs5_t *args, void *udata)
{
    unsigned int gup_flags = (unsigned int)args->arg4;
    char *buf = (char *)args->arg2;
    int len = (int)args->arg3;

    (void)udata;

    if (gup_flags & FOLL_WRITE)
        return;
    if (!buf || len <= 0)
        return;

    scrub_frida_signatures(buf, len);
}

void frida_mem_hide_install(void)
{
    access_remote_vm_fn = (void *)kallsyms_lookup_name("access_remote_vm");

    if (access_remote_vm_fn) {
        hook_err_t err = hook_wrap5(access_remote_vm_fn, NULL, after_access_remote_vm, NULL);
        if (err) {
            pr_err("KPM_FRIDA: hook access_remote_vm failed %d\n", err);
            access_remote_vm_fn = 0;
        }
    } else {
        pr_warn("KPM_FRIDA: access_remote_vm not found, mem hide skipped\n");
    }

    pr_info("KPM_FRIDA: mem hide installed\n");
}

void frida_mem_hide_uninstall(void)
{
    if (access_remote_vm_fn)
        unhook(access_remote_vm_fn);

    pr_info("KPM_FRIDA: mem hide uninstalled\n");
}
