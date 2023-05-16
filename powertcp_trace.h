#ifndef POWERTCP_TRACE_H
#define POWERTCP_TRACE_H

/* This header requires prior inclusion of vmlinux.h or linux/types.h. */

struct powertcp_trace_event {
	__u64 time;
	unsigned int sock_hash;
	__u32 cwnd;
	unsigned long rate;
	unsigned long p_norm;
	unsigned long p_smooth;
	unsigned long qlen;
	__u32 tx_bytes_diff;
	__u32 delta_t; /* careful: in ns */
	long rtt_grad; // long instead of unsigned long might truncate a huge rtt_grad
};

#endif
