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
		__field(u64, time)
		__field(unsigned int, hash)
		__field(u32, ack_seq)
		__field(u32, cwnd)
		__field(unsigned long, rate)
	),
	TP_fast_assign(
		const struct tcp_sock *tp = tcp_sk(sk);

		__entry->time = tp->tcp_mstamp;
		__entry->hash = sk->sk_hash;
		__entry->ack_seq = tp->snd_una;
		__entry->cwnd = tp->snd_cwnd;
		__entry->rate = sk->sk_pacing_rate;
	),
	TP_printk(
		"time=%llu us hash=%u ack_seq=%u: cwnd=%u rate=%lu bytes/s (~%lu Mbit/s)",
		__entry->time, __entry->hash, __entry->ack_seq, __entry->cwnd,
		__entry->rate, BITS_PER_BYTE * __entry->rate / MEGA)
);

TRACE_EVENT(norm_power,
	TP_PROTO(const struct sock *sk, long dt, long delta_t, long rtt,
		long rtt_grad, long base_rtt, long power_scale, long p_norm,
		long p_smooth),
	TP_ARGS(sk, dt, delta_t, rtt, rtt_grad, base_rtt, power_scale, p_norm,
		p_smooth),
	TP_STRUCT__entry(
		__field(u64, time)
		__field(unsigned int, hash)
		__field(long, dt)
		__field(long, delta_t)
		__field(long, rtt)
		__field(long, rtt_grad)
		__field(long, base_rtt)
		__field(long, power_scale)
		__field(long, p_norm)
		__field(long, p_smooth)
	),
	TP_fast_assign(
		const struct tcp_sock *tp = tcp_sk(sk);

		__entry->time = tp->tcp_mstamp;
		__entry->hash = sk->sk_hash;
		__entry->dt = dt;
		__entry->delta_t = delta_t;
		__entry->rtt = rtt;
		__entry->rtt_grad = rtt_grad;
		__entry->base_rtt = base_rtt;
		__entry->power_scale = power_scale;
		__entry->p_norm = p_norm;
		__entry->p_smooth = p_smooth;
	),
	TP_printk(
		"time=%llu us hash=%u: dt=%ld us delta_t=%ld us rtt=%ld us rtt_grad*%ld=%ld base_rtt=%ld us p_norm*%ld=%ld => p_smooth*%ld=%ld",
		__entry->time, __entry->hash, __entry->dt, __entry->delta_t,
		__entry->rtt, __entry->power_scale, __entry->rtt_grad, __entry->base_rtt,
		__entry->power_scale, __entry->p_norm, __entry->power_scale,
		__entry->p_smooth)
)

TRACE_EVENT(update_window,
	TP_PROTO(const struct sock *sk, u32 cwnd_old, long power_scale, long p_norm,
		u32 cwnd),
	TP_ARGS(sk, cwnd_old, power_scale, p_norm, cwnd),
	TP_STRUCT__entry(
		__field(u64, time)
		__field(unsigned int, hash)
		__field(u32, cwnd_old)
		__field(u32, snd_cwnd)
		__field(long, power_scale)
		__field(long, p_norm)
		__field(long, beta)
		__field(u32, cwnd)
	),
	TP_fast_assign(
		const struct powertcp *ca = inet_csk_ca(sk);
		const struct tcp_sock *tp = tcp_sk(sk);

		__entry->time = tp->tcp_mstamp;
		__entry->hash = sk->sk_hash;
		__entry->cwnd_old = cwnd_old;
		__entry->snd_cwnd = tp->snd_cwnd;
		__entry->power_scale = power_scale;
		__entry->p_norm = p_norm;
		__entry->beta = ca->beta;
		__entry->cwnd = cwnd;
	),
	TP_printk(
		"time=%llu us hash=%u: cwnd_old=%u cwnd=%u p_norm*%ld=%ld  beta=%ld => cwnd=%u",
		__entry->time, __entry->hash, __entry->cwnd_old, __entry->snd_cwnd,
		__entry->power_scale, __entry->p_norm, __entry->beta, __entry->cwnd)
);
// clang-format on

#endif /* _TRACE_POWERTCP_H */

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE tcp_powertcp_trace
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .

/* This part must be outside protection */
#include <trace/define_trace.h>
