#include "frida_hide.h"

#include "common.h"
#include <hook.h>
#include <kputils.h>
#include <syscall.h>

#include <linux/kallsyms.h>
#include <linux/printk.h>
#include <linux/string.h>

static void *show_map_vma_fn = 0;
static void *get_task_comm_fn = 0;

static int contains_token(const char *buf, size_t len, const char *token)
{
    size_t token_len;

    if (!buf || !token)
        return 0;

    token_len = strlen(token);
    if (token_len == 0 || len < token_len)
        return 0;

    for (size_t i = 0; i + token_len <= len; ++i) {
        if (!memcmp(buf + i, token, token_len))
            return 1;
    }

    return 0;
}

static int __attribute__((optimize("O0"))) is_hidden_map(struct seq_file *m, size_t prev_count)
{
    const char *block_str[] = {
        "frida",
        "gadget",
        "linjector",
        "gmain",
    };
    const char *start;
    size_t new_len;

    if (!m || !m->buf || m->count < prev_count)
        return 0;

    /* bounds check against seq_file buffer size */
    if (prev_count > m->size)
        return 0;

    start = m->buf + prev_count;
    new_len = m->count - prev_count;
    if (new_len == 0)
        return 0;

    /* clamp to m->size in case m->count was incremented beyond buffer */
    if (prev_count + new_len > m->size)
        new_len = m->size - prev_count;

    for (int i = 0; i < (int)(sizeof(block_str) / sizeof(block_str[0])); i++) {
        if (contains_token(start, new_len, block_str[i]))
            return 1;
    }

    return 0;
}

static void before_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;

    (void)udata;

    if (m && m->buf) {
        args->local.data0 = m->count;
        args->local.data1 = 1;
    } else {
        args->local.data1 = 0;
    }
}

static void after_show_map_vma(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;

    (void)udata;

    if (m && m->buf && args->local.data1) {
        size_t prev_count = (size_t)args->local.data0;
        if (is_hidden_map(m, prev_count))
            m->count = prev_count;
    }
}

static int is_hidden_comm(const char *comm)
{
    const char *ban_names[] = {
        "gum-js-loop",
        "pool-frida",
        "pool-spawner",
        "linjector",
        "gmain",
        "gdbus",
        "frida",
    };

    if (!comm)
        return 0;

    for (int i = 0; i < (int)(sizeof(ban_names) / sizeof(ban_names[0])); i++) {
        if (strstr(comm, ban_names[i]))
            return 1;
    }

    return 0;
}

static void __attribute__((optimize("O0"))) after_get_task_comm(hook_fargs3_t *args, void *udata)
{
    char *comm = (char *)args->arg0;
    size_t comm_buf_len = (size_t)args->arg1;
    const char *fake = "binder";
    size_t copy_len;

    (void)udata;

    if (!comm || comm_buf_len == 0 || !is_hidden_comm(comm))
        return;

    copy_len = strlen(fake);
    if (copy_len >= comm_buf_len)
        copy_len = comm_buf_len - 1;

    memcpy(comm, fake, copy_len);
    comm[copy_len] = '\0';
}

void frida_maps_hide_install(void)
{
    show_map_vma_fn = (void *)kallsyms_lookup_name("show_map_vma");
    get_task_comm_fn = (void *)kallsyms_lookup_name("__get_task_comm");

    if (show_map_vma_fn) {
        hook_err_t err = hook_wrap2(show_map_vma_fn, before_show_map_vma, after_show_map_vma, NULL);
        if (err) {
            pr_err("KPM_FRIDA: hook show_map_vma failed %d\n", err);
            show_map_vma_fn = 0;
        }
    } else {
        pr_warn("KPM_FRIDA: show_map_vma not found\n");
    }

    if (get_task_comm_fn) {
        hook_err_t err = hook_wrap3(get_task_comm_fn, NULL, after_get_task_comm, NULL);
        if (err) {
            pr_err("KPM_FRIDA: hook __get_task_comm failed %d\n", err);
            get_task_comm_fn = 0;
        }
    } else {
        pr_warn("KPM_FRIDA: __get_task_comm not found\n");
    }

    pr_info("KPM_FRIDA: frida hide installed\n");
}

void frida_maps_hide_uninstall(void)
{
    if (show_map_vma_fn)
        unhook(show_map_vma_fn);
    if (get_task_comm_fn)
        unhook(get_task_comm_fn);

    pr_info("KPM_FRIDA: frida hide uninstalled\n");
}
