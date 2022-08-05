// SPDX-License-Identifier: GPL-2.0 OR MIT
#undef TRACE_SYSTEM
#define TRACE_SYSTEM powertcp

#if !defined(_TRACE_POWERTCP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_POWERTCP_H

#include "tcp_powertcp.h"

#include <linux/tracepoint.h>
#include <net/sock.h>
#include <net/tcp.h>

// clang-format off
TRACE_EVENT(new_ack,
	TP_PROTO(const struct sock *sk),
	TP_ARGS(sk),
	TP_STRUCT__entry(
		__field(unsigned int, hash)
		__field(u32, ack_seq)
		__field(unsigned long, cwnd)
		__field(unsigned long, rate)
	),
	TP_fast_assign(
		const struct powertcp *ca = inet_csk_ca(sk);
		const struct tcp_sock *tp = tcp_sk(sk);

		__entry->hash = sk->sk_hash;
		__entry->ack_seq = tp->snd_una;
		__entry->cwnd = ca->snd_cwnd;
		__entry->rate = sk->sk_pacing_rate;
	),
	TP_printk(
		"hash=%u ack_seq=%u: cwnd*%lu=%lu rate=%lu bytes/s (~%lu Mbit/s)",
		__entry->hash, __entry->ack_seq, cwnd_scale, __entry->cwnd,
		__entry->rate, BITS_PER_BYTE * __entry->rate / MEGA)
);

TRACE_EVENT(norm_power,
	TP_PROTO(const struct sock *sk, unsigned long dt, unsigned long delta_t,
		unsigned long rtt, unsigned long rtt_grad, unsigned long base_rtt,
		unsigned long p_norm, unsigned long p_smooth),
	TP_ARGS(sk, dt, delta_t, rtt, rtt_grad, base_rtt, p_norm, p_smooth),
	TP_STRUCT__entry(
		__field(unsigned int, hash)
		__field(unsigned long, dt)
		__field(unsigned long, delta_t)
		__field(unsigned long, rtt)
		__field(unsigned long, rtt_grad)
		__field(unsigned long, base_rtt)
		__field(unsigned long, p_norm)
		__field(unsigned long, p_smooth)
	),
	TP_fast_assign(
		__entry->hash = sk->sk_hash;
		__entry->dt = dt;
		__entry->delta_t = delta_t;
		__entry->rtt = rtt;
		__entry->rtt_grad = rtt_grad;
		__entry->base_rtt = base_rtt;
		__entry->p_norm = p_norm;
		__entry->p_smooth = p_smooth;
	),
	TP_printk(
		"hash=%u: dt=%lu us delta_t=%lu us rtt=%lu us rtt_grad*%lu=%lu base_rtt=%lu us p_norm*%lu=%lu => p_smooth*%lu=%lu",
		__entry->hash, __entry->dt, __entry->delta_t, __entry->rtt, power_scale,
		__entry->rtt_grad, __entry->base_rtt, power_scale, __entry->p_norm,
		power_scale, __entry->p_smooth)
)

TRACE_EVENT(reset,
	TP_PROTO(unsigned int hash, enum tcp_ca_event ev,
		unsigned long base_rtt, unsigned long cwnd, unsigned long rate),
	TP_ARGS(hash, ev, base_rtt, cwnd, rate),
	TP_STRUCT__entry(
		__field(unsigned int, hash)
		__field(enum tcp_ca_event, ev)
		__field(unsigned long, base_rtt)
		__field(unsigned long, cwnd)
		__field(unsigned long, rate)
	),
	TP_fast_assign(
		__entry->hash = hash;
		__entry->ev = ev;
		__entry->base_rtt = base_rtt;
		__entry->cwnd = cwnd;
		__entry->rate = rate;
	),
	TP_printk(
		"hash=%u: ev=%d base_rtt=%lu cwnd*%lu=%lu rate=%lu bytes/s (~%lu Mbit/s)",
		__entry->hash, __entry->ev, __entry->base_rtt, cwnd_scale,
		__entry->cwnd, __entry->rate, BITS_PER_BYTE * __entry->rate / MEGA)
);

TRACE_EVENT(update_window,
	TP_PROTO(const struct sock *sk, unsigned long cwnd_old,
		unsigned long p_norm, unsigned long cwnd),
	TP_ARGS(sk, cwnd_old, p_norm, cwnd),
	TP_STRUCT__entry(
		__field(unsigned int, hash)
		__field(unsigned long, cwnd_old)
		__field(unsigned long, snd_cwnd)
		__field(unsigned long, p_norm)
		__field(unsigned long, beta)
		__field(unsigned long, cwnd)
	),
	TP_fast_assign(
		const struct powertcp *ca = inet_csk_ca(sk);
		const struct tcp_sock *tp = tcp_sk(sk);

		__entry->hash = sk->sk_hash;
		__entry->cwnd_old = cwnd_old;
		__entry->snd_cwnd = tp->snd_cwnd;
		__entry->p_norm = p_norm;
		__entry->beta = ca->beta;
		__entry->cwnd = cwnd;
	),
	TP_printk(
		"hash=%u: cwnd_old*%lu=%lu cwnd*%lu=%lu p_norm*%lu=%lu  beta=%lu => cwnd*%lu=%lu",
		__entry->hash, cwnd_scale, __entry->cwnd_old, cwnd_scale,
		__entry->snd_cwnd, power_scale, __entry->p_norm, __entry->beta,
		cwnd_scale, __entry->cwnd)
);
// clang-format on

#endif /* _TRACE_POWERTCP_H */

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE tcp_powertcp_trace
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .

/* This part must be outside protection */
#include <trace/define_trace.h>
