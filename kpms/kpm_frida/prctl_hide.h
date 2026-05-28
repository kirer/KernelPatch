/*
 * ⚠️⚠️⚠️  警告：此模块会导致手机死机，请勿编译到 KPM_FRIDA 中！ ⚠️⚠️⚠️
 *
 * hook prctl(PR_GET_NAME) 会触发内核死锁/panic（实测 Xiaomi 2201123C,
 * Android 13, Kernel 5.10.101）。
 *
 * 替代：frida_hide.c 的 __get_task_comm hook 效果等价且安全。
 *
 * 此文件保留仅供参考，不要 include。
 */

#ifndef __PRCTL_HIDE_H__
#define __PRCTL_HIDE_H__

void frida_prctl_hide_install(void);
void frida_prctl_hide_uninstall(void);

#endif
