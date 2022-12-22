// SPDX-License-Identifier: GPL-2.0 OR MIT

static const struct powertcp_int *get_int(struct sock *sk,
					  const struct powertcp_int *prev_int)
{
	return NULL;
}

static const struct powertcp_int *get_prev_int(struct sock *sk)
{
	return NULL;
}

static int int_impl_init(struct sock *sk)
{
	return 0;
}

static void int_impl_release(struct sock *sk)
{
}

static void int_impl_reset(powertcp_int_impl_t *int_impl, enum tcp_ca_event ev)
{
}

static void int_impl_update_old(powertcp_int_impl_t *int_impl)
{
}

static int register_int(struct tcp_congestion_ops *cong_ops)
{
	return 0;
}

static void unregister_int(struct tcp_congestion_ops *cong_ops)
{
}
