// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Common helpers for an eBPF CA.
 *
 * Similar to Linux' tools/testing/selftests/bpf/bpf_tcp_helpers.h but without
 * type definitions. vmlinux.h is used here for those. Most parts are copied
 * from net/tcp.h.
 */

#ifndef BPF_CA_HELPERS_H
#define BPF_CA_HELPERS_H

#include "vmlinux.h"

#define MEGA 1000000UL
#define SO_MAX_PACING_RATE 47
#define SOL_TCP 6
#define TCP_INFINITE_SSTHRESH 0x7fffffff
#define USEC_PER_SEC 1000000L

#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
#define BITS_PER_BYTE 8
#define BITS_PER_TYPE(type) (sizeof(type) * BITS_PER_BYTE)
#define BITS_TO_BYTES(nr) __KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(char))
#if __STDC_VERSION__ <= 201710L
#define BUILD_BUG_ON(cond) _Static_assert(!(cond), "BUILD BUG: " #cond)
#else
#define BUILD_BUG_ON(cond) static_assert(!(cond), "BUILD BUG: " #cond)
#endif
#define max(x, y) (((x) > (y)) ? (x) : (y))
#define max_t(type, x, y) max((type)(x), (type)(y))
#define min(x, y) (((x) < (y)) ? (x) : (y))
#define min_t(type, x, y) min((type)(x), (type)(y))

static inline bool before(__u32 seq1, __u32 seq2)
{
	return (__s32)(seq1 - seq2) < 0;
}
#define after(seq2, seq1) before(seq1, seq2)

static inline struct inet_connection_sock *inet_csk(const struct sock *sk)
{
	return (struct inet_connection_sock *)sk;
}

static inline void *inet_csk_ca(const struct sock *sk)
{
	return (void *)inet_csk(sk)->icsk_ca_priv;
}

/* Minimum RTT in usec. ~0 means not available. */
static inline __u32 tcp_min_rtt(const struct tcp_sock *tp)
{
	return tp->rtt_min.s[0].v;
}

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

static inline __u32 tcp_stamp_us_delta(__u64 t1, __u64 t0)
{
	return max_t(__s64, t1 - t0, 0);
}

#endif
