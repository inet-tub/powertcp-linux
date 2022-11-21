#ifndef POWERTCP_BPF_H
#define POWERTCP_BPF_H

/* This header requires prior inclusion of vmlinux.h or linux/types.h. */

struct powertcp_trace_event {
	__u32 time;
	unsigned int sk_hash;
	__u32 cwnd;
	unsigned long rate;
	unsigned long p_norm;
	unsigned long qlen;
};

#endif
