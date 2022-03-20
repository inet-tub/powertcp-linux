// SPDX-License-Identifier: GPL-2.0 OR MIT
#undef TRACE_SYSTEM
#define TRACE_SYSTEM powertcp

#if !defined(_TRACE_POWERTCP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_POWERTCP_H

#include <linux/tracepoint.h>

// clang-format off
TRACE_EVENT(new_ack,
	TP_PROTO(u64 time, u16 inet_id, u32 ack_seq, u32 cwnd, unsigned long rate),
	TP_ARGS(time, inet_id, ack_seq, cwnd, rate),
	TP_STRUCT__entry(
		__field(u64, time)
		__field(u16, inet_id)
		__field(u32, ack_seq)
		__field(u32, cwnd)
		__field(unsigned long, rate)
	),
	TP_fast_assign(
		__entry->time = time;
		__entry->inet_id = inet_id;
		__entry->ack_seq = ack_seq;
		__entry->cwnd = cwnd;
		__entry->rate = rate;
	),
	TP_printk("time=%llu ns inet_id=%u ack_seq=%u: cwnd=%u rate=%lu bytes/s (~%lu Mbit/s)",
		__entry->time, __entry->inet_id, __entry->ack_seq, __entry->cwnd,
		__entry->rate, BITS_PER_BYTE * __entry->rate / MEGA)
);

TRACE_EVENT(norm_power,
	TP_PROTO(u64 time, u16 inet_id, long dt, long delta_t, long rtt_grad,
		long base_rtt, long power_scale, long p_norm, long p_smooth,
		long result),
	TP_ARGS(time, inet_id, dt, delta_t, rtt_grad, base_rtt, power_scale, p_norm,
		p_smooth, result),
	TP_STRUCT__entry(
		__field(u64, time)
		__field(u16, inet_id)
		__field(long, dt)
		__field(long, delta_t)
		__field(long, rtt_grad)
		__field(long, base_rtt)
		__field(long, power_scale)
		__field(long, p_norm)
		__field(long, p_smooth)
		__field(long, result)
	),
	TP_fast_assign(
		__entry->time = time;
		__entry->inet_id = inet_id;
		__entry->dt = dt;
		__entry->delta_t = delta_t;
		__entry->rtt_grad = rtt_grad;
		__entry->base_rtt = base_rtt;
		__entry->power_scale = power_scale;
		__entry->p_norm = p_norm;
		__entry->p_smooth = p_smooth;
		__entry->result = result;
	),
	TP_printk(
		"time=%llu ns inet_id=%u: dt=%ld us delta_t=%ld us rtt_grad=%ld base_rtt=%ld us p_norm*%ld=%ld p_smooth*%ld=%ld => p_smooth*%ld=%ld",
		__entry->time, __entry->inet_id, __entry->dt, __entry->delta_t,
		__entry->rtt_grad, __entry->base_rtt,  __entry->power_scale,
		__entry->p_norm, __entry->power_scale, __entry->p_smooth,
		__entry->power_scale, __entry->result)
)

TRACE_EVENT(update_window,
	TP_PROTO(u64 time, u16 inet_id, u32 cwnd_old, u32 cwnd, long power_scale,
		long p_norm, long beta, u32 result),
	TP_ARGS(time, inet_id, cwnd_old, cwnd, power_scale, p_norm, beta, result),
	TP_STRUCT__entry(
		__field(u64, time)
		__field(u16, inet_id)
		__field(u32, cwnd_old)
		__field(u32, cwnd)
		__field(long, power_scale)
		__field(long, p_norm)
		__field(long, beta)
		__field(u32, result)
	),
	TP_fast_assign(
		__entry->time = time;
		__entry->inet_id = inet_id;
		__entry->cwnd_old = cwnd_old;
		__entry->cwnd = cwnd;
		__entry->power_scale = power_scale;
		__entry->p_norm = p_norm;
		__entry->beta = beta;
		__entry->result = result;
	),
	TP_printk(
		"time=%llu ns inet_id=%u: cwnd_old=%u cwnd=%u p_norm*%ld=%ld  beta=%ld => cwnd=%u",
		__entry->time, __entry->inet_id, __entry->cwnd_old, __entry->cwnd,
		__entry->power_scale, __entry->p_norm, __entry->beta, __entry->result)
);
// clang-format on

#endif /* _TRACE_POWERTCP_H */

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE tcp_powertcp_trace
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .

/* This part must be outside protection */
#include <trace/define_trace.h>
