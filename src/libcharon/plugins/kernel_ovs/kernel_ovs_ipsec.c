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

#include "kernel_ovs_ipsec.h"
#include "ovs_ctl.h"

#include <netinet/in.h>
#include <stdio.h>

#include <daemon.h>
#include <collections/linked_list.h>
#include <processing/jobs/callback_job.h>
#include <threading/mutex.h>
#include <utils/debug.h>

/** Default interval to check volume based lifetimes and ovs-vswitchd */
#define DEFAULT_POLL_INTERVAL 5

/** Maximum anti-replay window supported by Open vSwitch */
#define OVS_MAX_REPLAY_WINDOW 4096

typedef struct private_kernel_ovs_ipsec_t private_kernel_ovs_ipsec_t;

/**
 * Reference to the backend held by scheduled jobs, which may outlive it
 */
typedef struct {
	/** Number of references */
	refcount_t refs;
	/** The backend, NULL once destroyed */
	private_kernel_ovs_ipsec_t *ipsec;
} ipsec_ref_t;

static ipsec_ref_t *ipsec_ref_get(ipsec_ref_t *ref)
{
	ref_get(&ref->refs);
	return ref;
}

static void ipsec_ref_put(ipsec_ref_t *ref)
{
	if (ref_put(&ref->refs))
	{
		free(ref);
	}
}

/**
 * An SA installed in Open vSwitch
 */
typedef struct {
	/** Unique identifier, for expiration jobs */
	u_int id;
	/** SPI, in network order */
	uint32_t spi;
	/** Destination of the SA */
	host_t *dst;
	/** Interface ID, which binds the SA to an esp tunnel */
	uint32_t if_id;
	/** Inbound or outbound */
	bool inbound;
	/** Arguments of esp/sa-add, to reinstall it if ovs-vswitchd restarts.
	 *  They contain the key. */
	char *args[9];
	/** Lifetime */
	lifetime_cfg_t lifetime;
	/** Whether a soft expire was raised */
	bool rekeying;
} sa_entry_t;

struct private_kernel_ovs_ipsec_t {

	/**
	 * Public interface
	 */
	kernel_ovs_ipsec_t public;

	/**
	 * Connection to ovs-vswitchd
	 */
	ovs_ctl_t *ctl;

	/**
	 * Installed SAs, sa_entry_t
	 */
	linked_list_t *sas;

	/**
	 * Protects 'sas' and 'generation'
	 */
	mutex_t *mutex;

	/**
	 * Generation of the connection to ovs-vswitchd the SAs were installed on
	 */
	u_int generation;

	/**
	 * Next sa_entry_t id
	 */
	u_int next_id;

	/**
	 * Interval to poll volume lifetimes, in seconds
	 */
	u_int poll_interval;

	/**
	 * Reference for scheduled jobs
	 */
	ipsec_ref_t *ref;
};

static void sa_entry_destroy(sa_entry_t *entry)
{
	for (int i = 0; i < countof(entry->args); i++)
	{
		if (entry->args[i])
		{
			memwipe(entry->args[i], strlen(entry->args[i]));
			free(entry->args[i]);
		}
	}
	entry->dst->destroy(entry->dst);
	free(entry);
}

/**
 * Run "esp/sa-add" with the arguments of 'entry'
 */
static bool install_sa(private_kernel_ovs_ipsec_t *this, sa_entry_t *entry,
					   char **reply)
{
	return this->ctl->call(this->ctl, reply, "esp/sa-add", entry->args[0],
						   entry->args[1], entry->args[2], entry->args[3],
						   entry->args[4], entry->args[5], entry->args[6],
						   entry->args[7], entry->args[8], NULL);
}

static void raise_expire(sa_entry_t *entry, bool hard)
{
	charon->kernel->expire(charon->kernel, IPPROTO_ESP, entry->spi,
						   entry->dst, hard);
}

/**
 * If ovs-vswitchd restarted, it lost the SAs.  Reinstall them, with the
 * mutex held, and have the outbound ones rekeyed, as their sequence numbers
 * restart.
 */
static void check_restart(private_kernel_ovs_ipsec_t *this)
{
	enumerator_t *enumerator;
	sa_entry_t *entry;
	u_int generation;
	char *reply;

	generation = this->ctl->get_generation(this->ctl);
	if (generation == this->generation)
	{
		return;
	}
	if (this->generation)
	{
		DBG1(DBG_KNL, "kernel-ovs: ovs-vswitchd restarted, reinstalling "
			 "%d SAs", this->sas->get_count(this->sas));
		enumerator = this->sas->create_enumerator(this->sas);
		while (enumerator->enumerate(enumerator, &entry))
		{
			if (!install_sa(this, entry, &reply))
			{
				DBG1(DBG_KNL, "kernel-ovs: reinstalling SA %.8x failed: %s",
					 ntohl(entry->spi), reply);
			}
			free(reply);
			if (!entry->inbound && !entry->rekeying)
			{
				entry->rekeying = TRUE;
				raise_expire(entry, FALSE);
			}
		}
		enumerator->destroy(enumerator);
	}
	this->generation = generation;
}

static sa_entry_t *find_sa(private_kernel_ovs_ipsec_t *this, uint32_t spi,
						   host_t *dst)
{
	enumerator_t *enumerator;
	sa_entry_t *entry, *found = NULL;

	enumerator = this->sas->create_enumerator(this->sas);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->spi == spi && entry->dst->ip_equals(entry->dst, dst))
		{
			found = entry;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

static sa_entry_t *find_sa_by_id(private_kernel_ovs_ipsec_t *this, u_int id)
{
	enumerator_t *enumerator;
	sa_entry_t *entry, *found = NULL;

	enumerator = this->sas->create_enumerator(this->sas);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->id == id)
		{
			found = entry;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

/**
 * Delete 'entry' from Open vSwitch and from 'sas', with the mutex held
 */
static void remove_sa(private_kernel_ovs_ipsec_t *this, sa_entry_t *entry)
{
	char spi[16], dst[64], *reply;

	snprintf(spi, sizeof(spi), "spi=0x%08x", ntohl(entry->spi));
	snprintf(dst, sizeof(dst), "dst=%H", entry->dst);
	if (!this->ctl->call(this->ctl, &reply, "esp/sa-del",
						 entry->inbound ? "dir=in" : "dir=out", spi, dst,
						 NULL))
	{
		DBG1(DBG_KNL, "kernel-ovs: deleting SA %.8x failed: %s",
			 ntohl(entry->spi), reply);
	}
	free(reply);
	this->sas->remove(this->sas, entry, NULL);
	sa_entry_destroy(entry);
}

/**
 * Data of a time based expiration job
 */
typedef struct {
	ipsec_ref_t *ref;
	u_int id;
	bool hard;
} expire_job_t;

static void expire_job_destroy(expire_job_t *job)
{
	ipsec_ref_put(job->ref);
	free(job);
}

/**
 * Raise the expire event for the SA with 'id', and delete it if 'hard'
 */
static void expire_sa(private_kernel_ovs_ipsec_t *this, u_int id, bool hard)
{
	sa_entry_t *entry;
	uint32_t spi;
	host_t *dst;

	this->mutex->lock(this->mutex);
	entry = find_sa_by_id(this, id);
	if (!entry)
	{
		this->mutex->unlock(this->mutex);
		return;
	}
	spi = entry->spi;
	dst = entry->dst->clone(entry->dst);
	if (hard)
	{
		remove_sa(this, entry);
	}
	else
	{
		entry->rekeying = TRUE;
	}
	this->mutex->unlock(this->mutex);

	/* Without the mutex, as charon may call back, e.g. to delete the SA */
	charon->kernel->expire(charon->kernel, IPPROTO_ESP, spi, dst, hard);
	dst->destroy(dst);
}

static job_requeue_t expire_job(expire_job_t *job)
{
	if (job->ref->ipsec)
	{
		expire_sa(job->ref->ipsec, job->id, job->hard);
	}
	return JOB_REQUEUE_NONE;
}

static void schedule_expire(private_kernel_ovs_ipsec_t *this, u_int id,
							uint64_t timeout, bool hard)
{
	expire_job_t *job;

	INIT(job,
		.ref = ipsec_ref_get(this->ref),
		.id = id,
		.hard = hard,
	);
	lib->scheduler->schedule_job(lib->scheduler, (job_t*)
					callback_job_create((callback_job_cb_t)expire_job, job,
						(callback_job_cleanup_t)expire_job_destroy, NULL),
					timeout);
}

/**
 * Parse the reply of esp/sa-query
 */
static bool parse_usage(const char *reply, uint64_t *bytes, uint64_t *packets)
{
	unsigned long long b, p;

	if (!reply || sscanf(reply, "packets=%llu bytes=%llu", &p, &b) != 2)
	{
		return FALSE;
	}
	*bytes = b;
	*packets = p;
	return TRUE;
}

static bool query(private_kernel_ovs_ipsec_t *this, sa_entry_t *entry,
				  uint64_t *bytes, uint64_t *packets)
{
	char spi[16], dst[64], *reply;
	bool success;

	snprintf(spi, sizeof(spi), "spi=0x%08x", ntohl(entry->spi));
	snprintf(dst, sizeof(dst), "dst=%H", entry->dst);
	success = this->ctl->call(this->ctl, &reply, "esp/sa-query",
							  entry->inbound ? "dir=in" : "dir=out", spi, dst,
							  NULL) && parse_usage(reply, bytes, packets);
	free(reply);
	return success;
}

/**
 * Periodically check volume lifetimes, and whether ovs-vswitchd restarted
 */
static job_requeue_t poll_job(ipsec_ref_t *ref)
{
	private_kernel_ovs_ipsec_t *this = ref->ipsec;
	enumerator_t *enumerator;
	sa_entry_t *entry;
	linked_list_t *soft, *hard;
	uint64_t bytes, packets;
	char *reply;
	void *id;

	if (!this)
	{
		return JOB_REQUEUE_NONE;
	}
	soft = linked_list_create();
	hard = linked_list_create();

	this->mutex->lock(this->mutex);
	/* Any command detects a restart of ovs-vswitchd */
	if (this->sas->get_count(this->sas))
	{
		this->ctl->call(this->ctl, &reply, "esp/spi-alloc", NULL);
		free(reply);
	}
	check_restart(this);

	enumerator = this->sas->create_enumerator(this->sas);
	while (enumerator->enumerate(enumerator, &entry))
	{
		lifetime_cfg_t *lt = &entry->lifetime;

		if (!lt->bytes.life && !lt->packets.life &&
			!lt->bytes.rekey && !lt->packets.rekey)
		{
			continue;
		}
		if (!query(this, entry, &bytes, &packets))
		{
			continue;
		}
		if ((lt->bytes.life && bytes >= lt->bytes.life) ||
			(lt->packets.life && packets >= lt->packets.life))
		{
			hard->insert_last(hard, (void*)(uintptr_t)entry->id);
		}
		else if (!entry->rekeying &&
				 ((lt->bytes.rekey && bytes >= lt->bytes.rekey) ||
				  (lt->packets.rekey && packets >= lt->packets.rekey)))
		{
			entry->rekeying = TRUE;
			soft->insert_last(soft, (void*)(uintptr_t)entry->id);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	/* Raise the events without holding the mutex, as charon may call back */
	while (soft->remove_first(soft, &id) == SUCCESS)
	{
		expire_sa(this, (uintptr_t)id, FALSE);
	}
	while (hard->remove_first(hard, &id) == SUCCESS)
	{
		expire_sa(this, (uintptr_t)id, TRUE);
	}
	soft->destroy(soft);
	hard->destroy(hard);

	return JOB_RESCHEDULE(this->poll_interval);
}

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
	private_kernel_ovs_ipsec_t *this)
{
	return 0;
}

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_kernel_ovs_ipsec_t *this, host_t *src, host_t *dst,
	uint8_t protocol, uint32_t *spi)
{
	unsigned int value;
	char *reply;
	status_t status = FAILED;

	if (protocol != IPPROTO_ESP)
	{
		return NOT_SUPPORTED;
	}
	if (this->ctl->call(this->ctl, &reply, "esp/spi-alloc", NULL) &&
		reply && sscanf(reply, "%x", &value) == 1)
	{
		*spi = htonl(value);
		status = SUCCESS;
	}
	else
	{
		DBG1(DBG_KNL, "kernel-ovs: allocating SPI failed: %s", reply);
	}
	free(reply);
	return status;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_kernel_ovs_ipsec_t *this, host_t *src, host_t *dst,
	uint16_t *cpi)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_kernel_ovs_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_add_sa_t *data)
{
	sa_entry_t *entry;
	chunk_t key_hex;
	char *reply;
	int n = 0;

	if (id->proto != IPPROTO_ESP || data->mode != MODE_TUNNEL ||
		data->ipcomp != IPCOMP_NONE)
	{
		DBG1(DBG_KNL, "kernel-ovs: only ESP in tunnel mode is supported");
		return NOT_SUPPORTED;
	}
	if (data->enc_alg != ENCR_AES_GCM_ICV16 ||
		data->int_alg != AUTH_UNDEFINED)
	{
		DBG1(DBG_KNL, "kernel-ovs: only AES-GCM with a 16-byte ICV is "
			 "supported, configure e.g. esp_proposals = aes256gcm16");
		return NOT_SUPPORTED;
	}
	if (!id->if_id)
	{
		DBG1(DBG_KNL, "kernel-ovs: the CHILD_SA has no interface ID, "
			 "configure if_id_in and if_id_out as the esp_if_id of the "
			 "Open vSwitch tunnel");
		return FAILED;
	}

	INIT(entry,
		.spi = id->spi,
		.dst = id->dst->clone(id->dst),
		.if_id = id->if_id,
		.inbound = data->inbound,
		.lifetime = *data->lifetime,
	);

	key_hex = chunk_to_hex(data->enc_key, NULL, FALSE);
	if (asprintf(&entry->args[n++], "dir=%s", data->inbound ? "in" : "out")
			< 0 ||
		asprintf(&entry->args[n++], "spi=0x%08x", ntohl(id->spi)) < 0 ||
		asprintf(&entry->args[n++], "src=%H", id->src) < 0 ||
		asprintf(&entry->args[n++], "dst=%H", id->dst) < 0 ||
		asprintf(&entry->args[n++], "if_id=%u", id->if_id) < 0 ||
		asprintf(&entry->args[n++], "key=0x%.*s", (int)key_hex.len,
				 key_hex.ptr) < 0 ||
		asprintf(&entry->args[n++], "esn=%s", data->esn ? "yes" : "no")
			< 0 ||
		asprintf(&entry->args[n++], "replay=%u",
				 min(data->replay_window, OVS_MAX_REPLAY_WINDOW)) < 0 ||
		asprintf(&entry->args[n++], "encap=%s", data->encap ? "yes" : "no")
			< 0)
	{
		chunk_clear(&key_hex);
		sa_entry_destroy(entry);
		return FAILED;
	}
	chunk_clear(&key_hex);

	this->mutex->lock(this->mutex);
	check_restart(this);
	if (!install_sa(this, entry, &reply))
	{
		DBG1(DBG_KNL, "kernel-ovs: adding SA %.8x for if_id %u failed: %s",
			 ntohl(id->spi), id->if_id, reply);
		free(reply);
		this->mutex->unlock(this->mutex);
		sa_entry_destroy(entry);
		return FAILED;
	}
	free(reply);
	/* Installing it may have reconnected to a restarted ovs-vswitchd, which
	 * lost the other SAs */
	check_restart(this);
	entry->id = ++this->next_id;
	this->sas->insert_last(this->sas, entry);

	/* Time based lifetimes, see ipsec_sa_mgr in libipsec */
	if (entry->lifetime.time.life)
	{
		if (entry->lifetime.time.rekey &&
			entry->lifetime.time.rekey < entry->lifetime.time.life)
		{
			schedule_expire(this, entry->id, entry->lifetime.time.rekey,
							FALSE);
		}
		schedule_expire(this, entry->id, entry->lifetime.time.life, TRUE);
	}
	this->mutex->unlock(this->mutex);

	DBG2(DBG_KNL, "kernel-ovs: added %s SA %.8x for if_id %u",
		 data->inbound ? "inbound" : "outbound", ntohl(id->spi), id->if_id);
	return SUCCESS;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_kernel_ovs_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_update_sa_t *data)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_kernel_ovs_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_query_sa_t *data, uint64_t *bytes, uint64_t *packets,
	time_t *time)
{
	sa_entry_t *entry;
	uint64_t b, p;
	status_t status = NOT_FOUND;

	this->mutex->lock(this->mutex);
	entry = find_sa(this, id->spi, id->dst);
	if (entry && query(this, entry, &b, &p))
	{
		if (bytes)
		{
			*bytes = b;
		}
		if (packets)
		{
			*packets = p;
		}
		if (time)
		{
			*time = 0;
		}
		status = SUCCESS;
	}
	this->mutex->unlock(this->mutex);
	return status;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
	private_kernel_ovs_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_del_sa_t *data)
{
	sa_entry_t *entry;
	status_t status = NOT_FOUND;

	this->mutex->lock(this->mutex);
	entry = find_sa(this, id->spi, id->dst);
	if (entry)
	{
		remove_sa(this, entry);
		status = SUCCESS;
	}
	this->mutex->unlock(this->mutex);
	return status;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
	private_kernel_ovs_ipsec_t *this)
{
	sa_entry_t *entry;
	char *reply;

	this->mutex->lock(this->mutex);
	this->ctl->call(this->ctl, &reply, "esp/sa-flush", NULL);
	free(reply);
	while (this->sas->remove_first(this->sas, (void**)&entry) == SUCCESS)
	{
		sa_entry_destroy(entry);
	}
	this->mutex->unlock(this->mutex);
	return SUCCESS;
}

/* Open vSwitch forwards traffic according to its OpenFlow tables, so there
 * are no policies to install. */

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_kernel_ovs_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_manage_policy_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_kernel_ovs_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_query_policy_t *data, time_t *use_time)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
	private_kernel_ovs_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_manage_policy_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
	private_kernel_ovs_ipsec_t *this)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, bypass_socket, bool,
	private_kernel_ovs_ipsec_t *this, int fd, int family)
{
	/* IKE traffic goes through the host's network stack, which has no
	 * policies to bypass */
	return TRUE;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
	private_kernel_ovs_ipsec_t *this, int fd, int family, uint16_t port)
{
	/* Open vSwitch decapsulates ESP in UDP itself */
	return TRUE;
}

METHOD(kernel_ipsec_t, destroy, void,
	private_kernel_ovs_ipsec_t *this)
{
	sa_entry_t *entry;

	this->ref->ipsec = NULL;
	ipsec_ref_put(this->ref);
	while (this->sas->remove_first(this->sas, (void**)&entry) == SUCCESS)
	{
		sa_entry_destroy(entry);
	}
	this->sas->destroy(this->sas);
	this->ctl->destroy(this->ctl);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * Remove the SAs a previous charon left in Open vSwitch if it did not shut
 * down cleanly.  This charon does not know them, so nothing would ever rekey,
 * expire or delete them, and their keys would stay in ovs-vswitchd.
 */
static void flush_stale_sas(private_kernel_ovs_ipsec_t *this)
{
	char *reply;

	if (this->ctl->call(this->ctl, &reply, "esp/sa-flush", NULL))
	{
		DBG1(DBG_KNL, "kernel-ovs: removed any SAs left by a previous charon");
	}
	free(reply);
}

/*
 * Described in header.
 */
kernel_ovs_ipsec_t *kernel_ovs_ipsec_create()
{
	private_kernel_ovs_ipsec_t *this;

	INIT(this,
		.public = {
			.interface = {
				.get_features = _get_features,
				.get_spi = _get_spi,
				.get_cpi = _get_cpi,
				.add_sa  = _add_sa,
				.update_sa = _update_sa,
				.query_sa = _query_sa,
				.del_sa = _del_sa,
				.flush_sas = _flush_sas,
				.add_policy = _add_policy,
				.query_policy = _query_policy,
				.del_policy = _del_policy,
				.flush_policies = _flush_policies,
				.bypass_socket = _bypass_socket,
				.enable_udp_decap = _enable_udp_decap,
				.destroy = _destroy,
			},
		},
		.ctl = ovs_ctl_create(),
		.sas = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.poll_interval = lib->settings->get_int(lib->settings,
							"%s.plugins.kernel-ovs.poll_interval",
							DEFAULT_POLL_INTERVAL, lib->ns),
	);

	INIT(this->ref,
		.refs = 1,
		.ipsec = this,
	);
	flush_stale_sas(this);
	lib->scheduler->schedule_job(lib->scheduler, (job_t*)
					callback_job_create((callback_job_cb_t)poll_job,
						ipsec_ref_get(this->ref),
						(callback_job_cleanup_t)ipsec_ref_put, NULL),
					this->poll_interval);
	return &this->public;
}
