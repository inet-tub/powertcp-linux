// SPDX-License-Identifier: GPL-2.0 OR MIT

#include "tcp_int_common.h"
#include "tcp_int_common.bpf.h"

static const struct powertcp_int *get_int(struct sock *sk,
					  const struct powertcp_int *prev_int)
{
	struct ptcp_powertcp *ca = inet_csk_ca(sk);
	struct powertcp_int_impl *int_impl = &ca->int_impl;
	const struct tcp_sock *tp = tcp_sk(sk);
	/* Not using tcp_int_get_state() here since it uses
	 * BPF_SK_STORAGE_GET_F_CREATE. We might want to use a missing map entry as
	 * an indicator to fall back to RTT-PowerTCP.
	 */
	const struct tcp_int_state *tint =
		bpf_sk_storage_get(&map_tcp_int_state, sk, NULL, 0);

	if (tint) {
		u32 bandwidth = BITS_TO_BYTES(hop_bw);
#if USE_SWLAT_AS_TIMESTAMP
		u32 ts = tint->swlat;
#else
		u32 ts = tp->tcp_mstamp * NSEC_PER_USEC;
#endif
		u32 dt = (!prev_int ? tp->srtt_us * (1000u >> 3) :
					      ts - prev_int->hops[0].ts) &
			   max_ts;

		if (dt == 0) {
			int_impl->cached_int.n_hop = 0;
			return NULL;
		}

		int_impl->cached_int.n_hop = 1;
		/* TCP-INT does not provide an identification for the path. */
		/* TODO: Evaluate if it makes sense to use the switch ID as path ID.
		 * Could lead to a too frequently detected path change, though.
		 */
		int_impl->cached_int.path_id = 1;

		int_impl->cached_int.hops[0].bandwidth = bandwidth;
		int_impl->cached_int.hops[0].qlen = tint->qdepth;
		int_impl->cached_int.hops[0].ts = ts;
		/* In lack of a tx_bytes value, we estimate it here. A factor of
		 * MEGA/USEC_PER_SEC is cancelled in the calculation:
		 */
		int_impl->cached_int.hops[0].tx_bytes =
			bandwidth * tint->util / 100 / NSEC_PER_USEC * dt;

		return &int_impl->cached_int;
	} else {
		int_impl->cached_int.n_hop = 0;
	}

	return NULL;
}

static const struct powertcp_int *get_prev_int(struct sock *sk)
{
	struct ptcp_powertcp *ca = inet_csk_ca(sk);
	struct powertcp_int_impl *int_impl = &ca->int_impl;
	struct powertcp_int *prev_int = &int_impl->prev_int;

	if (prev_int->n_hop) {
		/* With TCP-INT, the difference in tx_bytes since last ACK is already
		 * estimated in get_int(). The previous value must be 0 so
		 * ptcp_norm_power() does not calculate a second difference with a
		 * value potentially coming from a different switch.
		 */
		prev_int->hops[0].tx_bytes = 0;
		return prev_int;
	}

	return NULL;
}

static int int_impl_init(struct sock *sk)
{
	return 0;
}

static void int_impl_release(struct sock *sk)
{
	/* no-op */
}

static void int_impl_reset(powertcp_int_impl_t *int_impl, enum tcp_ca_event ev)
{
	int_impl->prev_int.path_id = 0;
}

static void int_impl_update_old(powertcp_int_impl_t *int_impl)
{
	int_impl->prev_int = int_impl->cached_int;
}
