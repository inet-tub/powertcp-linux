// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * PowerTCP congestion control
 *
 * Based on the algorithm developed in:
 *    Addanki, V., O. Michel, and S. Schmid.
 *    "PowerTCP: Pushing the Performance Limits of Datacenter Networks."
 *    19th USENIX Symposium on Networked Systems Design and Implementation (NSDI 22).
 *    USENIX Association, 2022.
 * Available at: https://arxiv.org/pdf/2112.14309.pdf
 *
 * Implemented by:
 *   Jörn-Thorben Hinz, TU Berlin, 2022.
 */

#define POWERTCP_CONG_OPS_NAME_CONCAT2(prefix, cong_ops_name)                  \
	prefix##cong_ops_name
#define POWERTCP_CONG_OPS_NAME_CONCAT(prefix, cong_ops_name)                   \
	POWERTCP_CONG_OPS_NAME_CONCAT2(prefix, cong_ops_name)
#define POWERTCP_CONG_OPS_NAME(cong_ops_name)                                  \
	__stringify(POWERTCP_CONG_OPS_NAME_CONCAT(                             \
		POWERTCP_CONG_OPS_NAME_PREFIX, cong_ops_name))

static void clear_old_cwnds(struct sock *sk)
{
	struct powertcp *ca = inet_csk_ca(sk);
	ca->old_cwnd.cwnd = 0;
	ca->old_cwnd.snd_nxt = 0;
}

static unsigned long ewma(unsigned long weight, unsigned long weight_scale,
			  unsigned long value, unsigned long old_value)
{
	return (weight * value + (weight_scale - weight) * old_value) /
	       weight_scale;
}

/* Return the snd_cwnd that was set when the newly acknowledged segment(s) were
 * sent.
 */
static unsigned long get_cwnd(const struct sock *sk)
{
	const struct powertcp *ca = inet_csk_ca(sk);
	//const struct tcp_sock *tp = tcp_sk(sk);
	//u32 ack_seq = tp->snd_una;

	if (ca->old_cwnd.cwnd != 0 && ca->old_cwnd.snd_nxt != 0 /*&&
	    before(ca->old_cwnd.snd_nxt, ack_seq)*/) {
		return ca->old_cwnd.cwnd;
	}

	return ca->snd_cwnd;
}

/* Return the most recently measured RTT (in us). */
static unsigned long get_rtt(const struct sock *sk,
			     const struct rate_sample *rs)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	long rtt = rs->rtt_us; /* This is -1 if unavailable. */
	if (rtt < 0) {
		rtt = tp->srtt_us >> 3;
	}
	return rtt;
}

/* Limit a value to positive, non-zero numbers. */
static unsigned long not_zero(unsigned long val)
{
	return max(1UL, val);
}

static void set_cwnd(struct sock *sk, unsigned long cwnd,
		     struct powertcp_trace_event *trace_event)
{
	struct powertcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	ca->snd_cwnd = cwnd;
	cwnd /= cwnd_scale;
	cwnd = min_t(unsigned long, cwnd, tp->snd_cwnd_clamp);
	tp->snd_cwnd = not_zero(cwnd);

	if (tracing_enabled() && trace_event) {
		trace_event->cwnd = tp->snd_cwnd;
	}
}

/* Look for the base (~= minimum) RTT (in us). */
static void update_base_rtt(struct sock *sk)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 min_rtt;

	if (base_rtt > -1) {
		ca->base_rtt = base_rtt;
		return;
	}

	min_rtt = tcp_min_rtt(tp);
	if (min_rtt != ~0U) {
		ca->base_rtt = min_rtt;
		return;
	}

	min_rtt = tp->srtt_us >> 3;
	if (min_rtt) {
		ca->base_rtt = min_rtt;
		return;
	}

	/* bbr_init_pacing_rate_from_rtt() also uses this as fallback. */
	ca->base_rtt = USEC_PER_SEC;
}

static void update_beta(struct sock *sk, unsigned long old_base_rtt)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	if (beta < 0 &&
	    (ca->base_rtt < old_base_rtt || old_base_rtt == ULONG_MAX)) {
		unsigned long new_beta =
			BITS_TO_BYTES(cwnd_scale /* * MEGA */ * ca->host_bw *
				      ca->base_rtt / expected_flows) /
			tp->mss_cache /* / USEC_PER_SEC */;
		ca->beta = min(ca->beta, new_beta);
	}
}

static void reset(struct sock *sk, enum tcp_ca_event ev)
{
	struct powertcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if (ev == CA_EVENT_TX_START || ev == CA_EVENT_CWND_RESTART) {
		unsigned long old_base_rtt = ca->base_rtt;
		update_base_rtt(sk);
		update_beta(sk, old_base_rtt);
	}

	/* Only reset those values on a CA_EVENT_CWND_RESTART (used on
	 * initialization). Otherwise we would reset cwnd and rate too frequently if
	 * there are frequent CA_EVENT_TX_STARTs.
	 */
	if (ev == CA_EVENT_CWND_RESTART) {
		unsigned long rate = BITS_TO_BYTES(MEGA * ca->host_bw);
		unsigned long cwnd = cwnd_scale * rate * ca->base_rtt /
				     tp->mss_cache / USEC_PER_SEC;
		set_rate(sk, rate);
		set_cwnd(sk, cwnd, NULL);
		tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;

		ca->p_smooth = 0;

		clear_old_cwnds(sk);
	}
}

/* Update the list of recent snd_cwnds. */
static bool update_old(struct sock *sk, unsigned long p_smooth)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	if (before(ca->old_cwnd.snd_nxt, tp->snd_una) ||
	    (ca->old_cwnd.cwnd == 0 && ca->old_cwnd.snd_nxt == 0)) {
		ca->old_cwnd.cwnd = ca->snd_cwnd;
		ca->old_cwnd.snd_nxt = tp->snd_nxt;
	}

	ca->p_smooth = p_smooth;

	return true;
}

static unsigned long update_window(struct sock *sk, unsigned long cwnd_old,
				   unsigned long norm_power,
				   struct powertcp_trace_event *trace_event)
{
	const struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned long base_bdp = BITS_TO_BYTES(cwnd_scale) * ca->host_bw *
				 ca->base_rtt / tp->mss_cache;
	unsigned long cwnd;

	norm_power = not_zero(norm_power);
	cwnd = ewma(gamma, gamma_scale,
		    power_scale * cwnd_old / norm_power + ca->beta,
		    ca->snd_cwnd);
	cwnd = not_zero(cwnd);
	cwnd = min(cwnd, base_bdp);
	set_cwnd(sk, cwnd, trace_event);
	return cwnd;
}

static int ptcp_init(struct sock *sk)
{
	return int_impl_init(sk);
}

static unsigned long ptcp_norm_power(struct sock *sk,
				     const struct rate_sample *rs,
				     struct powertcp_trace_event *trace_event)
{
	const struct powertcp *ca = inet_csk_ca(sk);
	unsigned long delta_t = 0;
	unsigned long p_norm = 0;
	unsigned long p_smooth = ca->p_smooth;

	const struct powertcp_int *prev_int = get_prev_int(sk);
	const struct powertcp_int *this_int = get_int(sk, prev_int);
	int i;

	/* TODO: Do something helpful (a full reset?) when the path changes. */
	if (!this_int || !prev_int || this_int->path_id != prev_int->path_id) {
		/* Power calculations will be skipped for the first one or two ACKs.
		 * p_smooth will still be 0 then. This is intentional to have power
		 * smoothing start with a proper value (=p_norm) at the end of this
		 * function.
		 */
		return 0;
	}

	/* for each egress port i on the path */
	for (i = 0; i < this_int->n_hop && i < max_n_hops; ++i) {
		const struct powertcp_hop_int *hop_int = &this_int->hops[i];
		const struct powertcp_hop_int *prev_hop_int =
			&prev_int->hops[i];
		unsigned long dt =
			not_zero((hop_int->ts - prev_hop_int->ts) & max_ts);
		long queue_diff =
			(long)hop_int->qlen - (long)prev_hop_int->qlen;
		u32 tx_bytes_diff =
			(hop_int->tx_bytes - prev_hop_int->tx_bytes) &
			max_tx_bytes;
		/* The variable name "current" instead of lambda would conflict with a
		 * macro of the same name in asm-generic/current.h.
		 */
		unsigned long lambda =
			not_zero((unsigned long)max(
					 0l, queue_diff + (long)tx_bytes_diff) *
				 (NSEC_PER_SEC / dt));
		unsigned long bdp = hop_int->bandwidth * ca->base_rtt;
		unsigned long voltage = hop_int->qlen + bdp;
		unsigned long hop_p = lambda * voltage;
		unsigned long equilibrium = not_zero(
			(unsigned long)hop_int->bandwidth * hop_int->bandwidth /
			power_scale * MEGA * ca->base_rtt);
		unsigned long hop_p_norm = hop_p / equilibrium;
		if (hop_p_norm > p_norm || i == 0) {
			p_norm = hop_p_norm;
			delta_t = dt;

			if (tracing_enabled() && trace_event) {
				trace_event->qlen = hop_int->qlen;
				trace_event->tx_bytes_diff = tx_bytes_diff;
			}
		}
	}

	delta_t = min(delta_t, NSEC_PER_USEC * ca->base_rtt);
	p_norm = max(p_norm_cutoff, p_norm);
	p_smooth = p_smooth == 0 ? p_norm :
					 ewma(delta_t, NSEC_PER_USEC * ca->base_rtt,
					p_norm, p_smooth);

	if (tracing_enabled() && trace_event) {
		trace_event->delta_t = delta_t;
		trace_event->p_norm = p_norm;
		trace_event->p_smooth = p_smooth;
	}

	return p_smooth;
}

static void ptcp_release(struct sock *sk)
{
	int_impl_release(sk);
}

static void ptcp_reset(struct sock *sk, enum tcp_ca_event ev)
{
	struct ptcp_powertcp *ca = inet_csk_ca(sk);
	int_impl_reset(&ca->int_impl, ev);
	reset(sk, ev);
}

static bool ptcp_update_old(struct sock *sk, const struct rate_sample *rs,
			    unsigned long p_smooth)
{
	struct ptcp_powertcp *ca = inet_csk_ca(sk);
	int_impl_update_old(&ca->int_impl);
	return update_old(sk, p_smooth);
}

static unsigned long
ptcp_update_window(struct sock *sk, unsigned long cwnd_old,
		   unsigned long norm_power,
		   struct powertcp_trace_event *trace_event)
{
	return update_window(sk, cwnd_old, norm_power, trace_event);
}

static int rttptcp_init(struct sock *sk)
{
	return 0;
}

static unsigned long
rttptcp_norm_power(struct sock *sk, const struct rate_sample *rs,
		   struct powertcp_trace_event *trace_event)
{
	struct rttptcp_powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned long dt, rtt_grad, p_norm, delta_t;
	unsigned long p_smooth = ca->p_smooth;
	unsigned long rtt_us;

	if (before(tp->snd_una, ca->last_updated)) {
		return p_smooth;
	}

	ca->t = get_tstamp(sk);
	rtt_us = get_rtt(sk, rs);
	/* Timestamps are always increasing here, logically. So we want to have
	 * unsigned wrap-around when it's time and don't use tcp_stamp_us_delta().
	 */
	dt = not_zero(ca->t - ca->t_prev);
	delta_t = min(dt, ca->base_rtt * NSEC_PER_USEC);
	if (ca->prev_rtt_us <= rtt_us) {
		rtt_grad = NSEC_PER_USEC * power_scale *
			   (rtt_us - ca->prev_rtt_us) / dt;
		p_norm = (rtt_grad + power_scale) * rtt_us / ca->base_rtt;
	} else {
		/* Separate code path for negative rtt_grad since BPF does not support
		 * division by signed numbers.
		 */
		rtt_grad = NSEC_PER_USEC * power_scale *
			   (ca->prev_rtt_us - rtt_us) / dt;
		p_norm = (power_scale - min(power_scale, rtt_grad)) * rtt_us /
			 ca->base_rtt;
	}
	p_norm = max(p_norm_cutoff, p_norm);

	/* powertcp.p_smooth is initialized with 0, we don't want to smooth for the
	 * very first calculation.
	 */
	p_smooth = p_smooth == 0 ? p_norm :
				   ewma(delta_t, NSEC_PER_USEC * ca->base_rtt,
					p_norm, p_smooth);

	if (tracing_enabled() && trace_event) {
		trace_event->delta_t = delta_t;
		trace_event->p_norm = p_norm;
		trace_event->p_smooth = p_smooth;
	}

	return p_smooth;
}

static void rttptcp_release(struct sock *sk)
{
	/* no-op */
}

static void rttptcp_reset(struct sock *sk, enum tcp_ca_event ev)
{
	struct rttptcp_powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	reset(sk, ev);

	/* Only reset those on initialization. */
	if (ev == CA_EVENT_CWND_RESTART) {
		// TODO: Evaluate if it actually improves performance of the algorithm
		// to reset those two values only on CA_EVENT_CWND_RESTART:
		ca->last_updated = tp->snd_nxt;
		ca->prev_rtt_us = tp->srtt_us >> 3;
	}

	ca->t_prev = ca->t;
}

static bool rttptcp_update_old(struct sock *sk, const struct rate_sample *rs,
			       unsigned long p_smooth)
{
	struct rttptcp_powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	if (before(tp->snd_una, ca->last_updated)) {
		return false;
	}

	update_old(sk, p_smooth);

	ca->last_updated = tp->snd_nxt;
	ca->prev_rtt_us = get_rtt(sk, rs);
	// TODO: There are multiple timestamps available here. Is there a better one?
	ca->t_prev = ca->t;

	return true;
}

static unsigned long
rttptcp_update_window(struct sock *sk, unsigned long cwnd_old,
		      unsigned long norm_power,
		      struct powertcp_trace_event *trace_event)
{
	struct rttptcp_powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	if (before(tp->snd_una, ca->last_updated)) {
		return ca->snd_cwnd;
	}

	return update_window(sk, cwnd_old, norm_power, trace_event);
}

#define DEFINE_POWERTCP_VARIANT(func_prefix, cong_ops_name)                    \
	void POWERTCP_CONG_OPS_FUNC(powertcp_##func_prefix##_cwnd_event,       \
				    struct sock *sk, enum tcp_ca_event ev)     \
	{                                                                      \
		struct powertcp *ca = inet_csk_ca(sk);                         \
                                                                               \
		if (POWERTCP_UNLIKELY(ca->host_bw == 0)) {                     \
			return;                                                \
		}                                                              \
                                                                               \
		if (ev == CA_EVENT_TX_START) {                                 \
			func_prefix##_reset(sk, ev);                           \
		}                                                              \
	}                                                                      \
                                                                               \
	void POWERTCP_CONG_OPS_FUNC(powertcp_##func_prefix##_init,             \
				    struct sock *sk)                           \
	{                                                                      \
		struct powertcp *ca = inet_csk_ca(sk);                         \
                                                                               \
		BUILD_BUG_ON(sizeof(struct powertcp) > ICSK_CA_PRIV_SIZE);     \
		BUILD_BUG_ON(sizeof(struct func_prefix##_powertcp) >           \
			     ICSK_CA_PRIV_SIZE);                               \
                                                                               \
		func_prefix##_init(sk);                                        \
                                                                               \
		ca->base_rtt = ULONG_MAX;                                      \
		ca->beta = beta < 0 ? ULONG_MAX : beta * cwnd_scale;           \
		ca->host_bw = get_host_bw(sk);                                 \
                                                                               \
		func_prefix##_reset(sk, CA_EVENT_CWND_RESTART);                \
                                                                               \
		require_hwtstamps(sk);                                         \
		require_pacing(sk);                                            \
	}                                                                      \
                                                                               \
	void POWERTCP_CONG_OPS_FUNC(powertcp_##func_prefix##_cong_control,     \
				    struct sock *sk,                           \
				    const struct rate_sample *rs)              \
	{                                                                      \
		struct powertcp *ca = inet_csk_ca(sk);                         \
		const struct tcp_sock *tp = tcp_sk(sk);                        \
		unsigned long cwnd_old;                                        \
		unsigned long norm_power;                                      \
		unsigned long cwnd;                                            \
		unsigned long rate;                                            \
		bool updated;                                                  \
		struct powertcp_trace_event trace_event = {};                  \
                                                                               \
		if (POWERTCP_UNLIKELY(ca->host_bw == 0)) {                     \
			return;                                                \
		}                                                              \
                                                                               \
		cwnd_old = get_cwnd(sk);                                       \
		norm_power = func_prefix##_norm_power(sk, rs, &trace_event);   \
		if (norm_power) {                                              \
			cwnd = func_prefix##_update_window(                    \
				sk, cwnd_old, norm_power, &trace_event);       \
			rate = (USEC_PER_SEC * cwnd * tp->mss_cache) /         \
			       ca->base_rtt / cwnd_scale;                      \
			set_rate(sk, rate);                                    \
		}                                                              \
                                                                               \
		updated = func_prefix##_update_old(sk, rs, norm_power);        \
                                                                               \
		if (tracing_enabled() && updated && norm_power) {              \
			trace_event.rate = rate;                               \
			trace_event.sock_hash = sk->__sk_common.skc_hash;      \
			output_trace_event(&trace_event);                      \
		}                                                              \
	}                                                                      \
                                                                               \
	void POWERTCP_CONG_OPS_FUNC(powertcp_##func_prefix##_release,          \
				    struct sock *sk)                           \
	{                                                                      \
		const struct powertcp *ca = inet_csk_ca(sk);                   \
                                                                               \
		if (POWERTCP_UNLIKELY(ca->host_bw == 0)) {                     \
			return;                                                \
		}                                                              \
                                                                               \
		clear_old_cwnds(sk);                                           \
                                                                               \
		func_prefix##_release(sk);                                     \
	}                                                                      \
                                                                               \
	POWERTCP_CONG_OPS_ATTRS struct tcp_congestion_ops cong_ops_name = {    \
		.cong_avoid = POWERTCP_CONG_OPS_FUNC_PTR powertcp_cong_avoid,  \
		.cong_control = POWERTCP_CONG_OPS_FUNC_PTR                     \
			powertcp_##func_prefix##_cong_control,                 \
		.cwnd_event = POWERTCP_CONG_OPS_FUNC_PTR                       \
			powertcp_##func_prefix##_cwnd_event,                   \
		.init = POWERTCP_CONG_OPS_FUNC_PTR                             \
			powertcp_##func_prefix##_init,                         \
		.name = POWERTCP_CONG_OPS_NAME(cong_ops_name),                 \
		.release = POWERTCP_CONG_OPS_FUNC_PTR                          \
			powertcp_##func_prefix##_release,                      \
		.ssthresh = POWERTCP_CONG_OPS_FUNC_PTR powertcp_ssthresh,      \
		.undo_cwnd = POWERTCP_CONG_OPS_FUNC_PTR powertcp_undo_cwnd,    \
	}

u32 POWERTCP_CONG_OPS_FUNC(powertcp_ssthresh, struct sock *sk)
{
	/* We don't do slow starts here! */
	return TCP_INFINITE_SSTHRESH;
}

u32 POWERTCP_CONG_OPS_FUNC(powertcp_undo_cwnd, struct sock *sk)
{
	/* Never undo after a loss. */
	return tcp_sk(sk)->snd_cwnd;
}

DEFINE_POWERTCP_VARIANT(ptcp, powertcp);

/* Cannot name it rtt_powertcp due to the size limit for
 * tcp_congestion_ops.name. */
DEFINE_POWERTCP_VARIANT(rttptcp, rttpowertcp);
