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
 * @defgroup kernel_ovs kernel_ovs
 * @ingroup cplugins
 *
 * @defgroup kernel_ovs_plugin kernel_ovs_plugin
 * @{ @ingroup kernel_ovs
 */

#ifndef KERNEL_OVS_PLUGIN_H_
#define KERNEL_OVS_PLUGIN_H_

#include <library.h>
#include <plugins/plugin.h>

typedef struct kernel_ovs_plugin_t kernel_ovs_plugin_t;

/**
 * IPsec backend for the ESP tunnels of Open vSwitch's userspace datapath.
 */
struct kernel_ovs_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** KERNEL_OVS_PLUGIN_H_ @}*/
