/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "shield_utils.h"

void *(*kpm_vmalloc)(unsigned long size) = 0;
void (*kpm_vfree)(void *ptr) = 0;
int (*kpm_arch_copy_from_user)(void *to, const void __user *from, unsigned long n) = 0;
