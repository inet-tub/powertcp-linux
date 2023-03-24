/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Constants and default values common to both PowerTCP implementations.
 */
#ifndef POWERTCP_DEFS_H
#define POWERTCP_DEFS_H

static const unsigned long cwnd_scale = (1UL << 10);
static const unsigned long fallback_host_bw = 1000; /* Mbit/s */
static const unsigned long gamma_scale = (1UL << 10);
static const unsigned long power_scale = (1UL << 16);
static const unsigned long p_norm_cutoff = 0.01 * power_scale;

/* Avoid an "initializer element is not constant" error with gcc before 8.1 by
 * using an enum instead of static const variables. No, I don't want to use
 * macros for constants here :-)
 */
enum {
	default_base_rtt = -1, /* us */
	default_beta = -1, /* Number of packets */
	default_expected_flows = 10,
	default_gamma = 921, /* ~= 0.9 * gamma_scale */
	default_hop_bw = 1000, /* Mbit/s */
	default_host_bw = 1000, /* Mbit/s */
};

#endif /* POWERTCP_DEFS_H */
