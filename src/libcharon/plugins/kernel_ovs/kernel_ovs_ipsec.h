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
 * @defgroup kernel_ovs_ipsec_i kernel_ovs_ipsec
 * @{ @ingroup kernel_ovs
 */

#ifndef KERNEL_OVS_IPSEC_H_
#define KERNEL_OVS_IPSEC_H_

#include <kernel/kernel_ipsec.h>

typedef struct kernel_ovs_ipsec_t kernel_ovs_ipsec_t;

/**
 * IPsec backend that installs SAs in the ESP tunnels of Open vSwitch's
 * userspace datapath, e.g. OVS-DPDK.
 */
struct kernel_ovs_ipsec_t {

	/**
	 * Implements kernel_ipsec_t interface
	 */
	kernel_ipsec_t interface;
};

/**
 * Create a kernel_ovs_ipsec_t instance.
 *
 * @return			kernel_ovs_ipsec_t instance
 */
kernel_ovs_ipsec_t *kernel_ovs_ipsec_create();

#endif /** KERNEL_OVS_IPSEC_H_ @}*/
