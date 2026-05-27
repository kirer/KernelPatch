/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * hide_net.c - 闅愯棌鎸囧畾缃戠粶鐗瑰緛
 *
 * 1. /proc/net/tcp  鈥?闅愯棌 127.0.0.1:12708 (0100007F:31A4) 鍥炵幆杩炴帴
 * 2. /proc/net/unix 鈥?闅愯棌鎸囧畾鎶借薄 socket
 *
 * 浣跨敤鍜?hide_maps.c 鐩稿悓鐨?seq_file->show hook + count 鍥炴粴鎶€鏈€?
 */

#include "hide_maps.h"   /* seq_file / seq_operations 瀹氫箟 */
#include "kpm_utils.h"

#include <ksyms.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include <hook.h>

#define TAG "KPM_HIDE/net"

/* ========== kallsyms resolved pointers ========== */

static struct seq_operations *tcp4_seq_ops;
static struct seq_operations *tcp6_seq_ops;
static struct seq_operations *unix_seq_ops;

static int (*orig_tcp4_show)(struct seq_file *m, void *v);
static int (*orig_tcp6_show)(struct seq_file *m, void *v);
static int (*orig_unix_show)(struct seq_file *m, void *v);

/* ========== TCP 琛岃繃婊?========== */

/*
 * /proc/net/tcp 姣忚鏍煎紡:
 *   sl  local_address rem_address   st tx_queue ...
 *   0: 0100007F:31A4 0100007F:XXXX 01 ...
 *
 * 12708 = 0x31A4
 * 127.0.0.1 = 0100007F (灏忕鍗佸叚杩涘埗)
 *
 * 杩囨护鏉′欢: 鏈湴鍦板潃鍖呭惈 ":31A4" (绔彛 12708)
 */
static int should_hide_tcp_line(const char *line) {
    /* 璺宠繃 header 琛?(浠?"  sl" 寮€澶? */
    if (strstr(line, "local_address"))
        return 0;

    /* 杩囨护鍖呭惈绔彛 31A4 鐨勮 */
    if (strstr(line, ":31A4"))
        return 1;

    return 0;
}

/* ========== Unix socket 琛岃繃婊?========== */

/*
 * /proc/net/unix 姣忚鏍煎紡:
 *   Num RefCount Protocol Flags Type St Inode Path
 *   ...                                      @tool_patcher
 *
 * 杩囨护鏉′欢: 璺緞鍖呭惈鎸囧畾 socket 鏍囪
 */
static int should_hide_unix_line(const char *line) {
    /* 璺宠繃 header 琛?*/
    if (strstr(line, "RefCount"))
        return 0;

    if (strstr(line, "wwb"))
        return 1;

    return 0;
}

/* ========== 閫氱敤 seq_file show 杩囨护鍣?========== */

/*
 * 閫氱敤鐨?seq_file show hook: 璋冪敤鍘熷 show 鍚庢鏌ヨ緭鍑猴紝
 * 濡傛灉鍖归厤杩囨护鏉′欢鍒欏洖婊?m->count 闅愯棌璇ヨ銆?
 */
static int filtered_show(struct seq_file *m, void *v,
                         int (*orig_show)(struct seq_file *, void *),
                         int (*should_hide)(const char *),
                         const char *label) {
    if (!is_app_process())
        return orig_show(m, v);

    size_t start = m->count;
    int ret = orig_show(m, v);
    size_t end = m->count;

    if (end <= start || !kpm_vmalloc)
        return ret;

    size_t len = end - start;
    char *line = kpm_vmalloc(len + 1);
    if (!line)
        return ret;

    for (size_t i = 0; i < len; i++)
        line[i] = m->buf[start + i];
    line[len] = '\0';

    if (should_hide(line)) {
        m->count = start;
        pr_info(TAG ": %s hidden (uid=%d, %zu bytes)\n", label, current_uid(), len);
    }

    kpm_vfree(line);
    return ret;
}

/* ========== hooked show 鍑芥暟 ========== */

static int kpm_tcp4_show(struct seq_file *m, void *v) {
    return filtered_show(m, v, orig_tcp4_show, should_hide_tcp_line, "tcp");
}

static int kpm_tcp6_show(struct seq_file *m, void *v) {
    return filtered_show(m, v, orig_tcp6_show, should_hide_tcp_line, "tcp6");
}

static int kpm_unix_show(struct seq_file *m, void *v) {
    return filtered_show(m, v, orig_unix_show, should_hide_unix_line, "unix");
}

/* ========== init / exit ========== */

int hide_net_init(void) {
    /* === /proc/net/tcp === */
    tcp4_seq_ops = (struct seq_operations *)kallsyms_lookup_name("tcp4_seq_ops");
    if (tcp4_seq_ops) {
        orig_tcp4_show = tcp4_seq_ops->show;
        fp_hook((uintptr_t)&tcp4_seq_ops->show, (void *)kpm_tcp4_show,
                (void **)&orig_tcp4_show);
        pr_info(TAG ": tcp4 hook installed (orig=%p)\n", orig_tcp4_show);
    } else {
        pr_info(TAG ": tcp4_seq_ops not found, trying tcp_seq_ops\n");
        /* 閮ㄥ垎鍐呮牳鐗堟湰绗﹀彿鍚嶄笉鍚?*/
        tcp4_seq_ops = (struct seq_operations *)kallsyms_lookup_name("tcp_seq_ops");
        if (tcp4_seq_ops) {
            orig_tcp4_show = tcp4_seq_ops->show;
            fp_hook((uintptr_t)&tcp4_seq_ops->show, (void *)kpm_tcp4_show,
                    (void **)&orig_tcp4_show);
            pr_info(TAG ": tcp_seq_ops hook installed (orig=%p)\n", orig_tcp4_show);
        } else {
            pr_info(TAG ": tcp seq_ops not found\n");
        }
    }

    /* === /proc/net/tcp6 === */
    tcp6_seq_ops = (struct seq_operations *)kallsyms_lookup_name("tcp6_seq_ops");
    if (tcp6_seq_ops) {
        orig_tcp6_show = tcp6_seq_ops->show;
        fp_hook((uintptr_t)&tcp6_seq_ops->show, (void *)kpm_tcp6_show,
                (void **)&orig_tcp6_show);
        pr_info(TAG ": tcp6 hook installed (orig=%p)\n", orig_tcp6_show);
    } else {
        pr_info(TAG ": tcp6_seq_ops not found\n");
    }

    /* === /proc/net/unix === */
    unix_seq_ops = (struct seq_operations *)kallsyms_lookup_name("unix_seq_ops");
    if (unix_seq_ops) {
        orig_unix_show = unix_seq_ops->show;
        fp_hook((uintptr_t)&unix_seq_ops->show, (void *)kpm_unix_show,
                (void **)&orig_unix_show);
        pr_info(TAG ": unix hook installed (orig=%p)\n", orig_unix_show);
    } else {
        pr_info(TAG ": unix_seq_ops not found\n");
    }

    return 0;
}

void hide_net_exit(void) {
    if (tcp4_seq_ops && orig_tcp4_show) {
        fp_unhook((uintptr_t)&tcp4_seq_ops->show, orig_tcp4_show);
        pr_info(TAG ": tcp4 hook removed\n");
    }
    if (tcp6_seq_ops && orig_tcp6_show) {
        fp_unhook((uintptr_t)&tcp6_seq_ops->show, orig_tcp6_show);
        pr_info(TAG ": tcp6 hook removed\n");
    }
    if (unix_seq_ops && orig_unix_show) {
        fp_unhook((uintptr_t)&unix_seq_ops->show, orig_unix_show);
        pr_info(TAG ": unix hook removed\n");
    }
}
