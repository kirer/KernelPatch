/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _HIDE_MAPS_H
#define _HIDE_MAPS_H

#include <ktypes.h>

/* ========== seq_file minimal definition ========== */

typedef struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
    size_t pad_until;
    long long index;
    long long read_pos;
} seq_file;

struct seq_operations {
    void *(*start)(struct seq_file *m, long long *pos);
    void (*stop)(struct seq_file *m, void *v);
    void *(*next)(struct seq_file *m, void *v, long long *pos);
    int (*show)(struct seq_file *m, void *v);
};

/* ========== module API ========== */

int hide_maps_init(void);
void hide_maps_exit(void);

#endif /* _HIDE_MAPS_H */
