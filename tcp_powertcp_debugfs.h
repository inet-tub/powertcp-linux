// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * PowerTCP debugfs interface
 *
 * Implemented by:
 *   Jörn-Thorben Hinz, TU Berlin, 2022.
 */

#ifndef _TCP_POWERTCP_DEBUGFS_H
#define _TCP_POWERTCP_DEBUGFS_H

#include <linux/types.h>

#if IS_ENABLED(CONFIG_DEBUG_FS)

void powertcp_debugfs_exit(void);
void powertcp_debugfs_init(void);
void powertcp_debugfs_update(u32 ack_seq, u32 cwnd, unsigned long rate);

#else

static inline void powertcp_debugfs_exit(void)
{
}

static inline void powertcp_debugfs_init(void)
{
}

static inline void powertcp_debugfs_update(u32 ack_seq, u32 cwnd,
					   unsigned long rate)
{
}

#endif

#endif /* _TCP_POWERTCP_DEBUGFS_H */
