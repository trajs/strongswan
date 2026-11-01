/*
 * Copyright (C) 2026 The kernel-ovs authors
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup ovs_ctl ovs_ctl
 * @{ @ingroup kernel_ovs
 */

#ifndef OVS_CTL_H_
#define OVS_CTL_H_

#include <library.h>

typedef struct ovs_ctl_t ovs_ctl_t;

/**
 * Client for the unixctl control socket of ovs-vswitchd (JSON-RPC 1.0).
 */
struct ovs_ctl_t {

	/**
	 * Run an ovs-vswitchd command.
	 *
	 * Reconnects if the connection was lost, e.g. because ovs-vswitchd
	 * restarted, in which case the generation number increases.
	 *
	 * @param reply		allocated reply, or error message, or NULL
	 * @param method	command, e.g. "esp/sa-add"
	 * @param ...		string arguments, terminated by NULL
	 * @return			TRUE if the command succeeded
	 */
	bool (*call)(ovs_ctl_t *this, char **reply, const char *method, ...);

	/**
	 * Get the number of connections made to ovs-vswitchd so far.
	 *
	 * @return			generation number
	 */
	u_int (*get_generation)(ovs_ctl_t *this);

	/**
	 * Destroy an ovs_ctl_t.
	 */
	void (*destroy)(ovs_ctl_t *this);
};

/**
 * Create an ovs_ctl_t, configured by the kernel-ovs plugin's settings.
 */
ovs_ctl_t *ovs_ctl_create();

#endif /** OVS_CTL_H_ @}*/
