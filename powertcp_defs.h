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

static const int default_base_rtt = -1; /* us */
static const int default_beta = -1; /* Number of packets */
static const int default_expected_flows = 10;
static const int default_gamma = 0.9 * gamma_scale;
static const int default_hop_bw = 1000; /* Mbit/s */
static const int default_host_bw = 1000; /* Mbit/s */

#endif /* POWERTCP_DEFS_H */
