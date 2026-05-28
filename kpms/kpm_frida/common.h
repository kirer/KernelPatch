#ifndef __COMMON_H__
#define __COMMON_H__

#include <ktypes.h>

struct seq_file {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
};

enum pid_type {
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};

struct pid_namespace;
struct sockaddr_in {
    short            sin_family;
    unsigned short   sin_port;
    unsigned int     sin_addr;
    char             sin_zero[8];
};

#endif
