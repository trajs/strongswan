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

#include "ovs_ctl.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include <daemon.h>
#include <threading/mutex.h>
#include <utils/debug.h>

/** Timeout for a reply from ovs-vswitchd, in seconds */
#define OVS_CTL_TIMEOUT 5

typedef struct private_ovs_ctl_t private_ovs_ctl_t;

struct private_ovs_ctl_t {

	/**
	 * Public interface
	 */
	ovs_ctl_t public;

	/**
	 * Serializes requests on the connection
	 */
	mutex_t *mutex;

	/**
	 * Connected socket, or -1
	 */
	int fd;

	/**
	 * Number of connections made
	 */
	u_int generation;

	/**
	 * JSON-RPC id of the next request
	 */
	u_int next_id;

	/**
	 * Configured socket path, or NULL to find it from the pidfile
	 */
	char *socket;

	/**
	 * Run directory of ovs-vswitchd
	 */
	char *rundir;
};

/**
 * Find the control socket of the running ovs-vswitchd
 */
static char *get_socket_path(private_ovs_ctl_t *this)
{
	char pidfile[PATH_MAX], *path;
	FILE *file;
	int pid;

	if (this->socket)
	{
		return strdup(this->socket);
	}
	snprintf(pidfile, sizeof(pidfile), "%s/ovs-vswitchd.pid", this->rundir);
	file = fopen(pidfile, "r");
	if (!file)
	{
		DBG1(DBG_KNL, "kernel-ovs: unable to open %s: %s", pidfile,
			 strerror(errno));
		return NULL;
	}
	if (fscanf(file, "%d", &pid) != 1)
	{
		DBG1(DBG_KNL, "kernel-ovs: no pid in %s", pidfile);
		fclose(file);
		return NULL;
	}
	fclose(file);
	if (asprintf(&path, "%s/ovs-vswitchd.%d.ctl", this->rundir, pid) < 0)
	{
		return NULL;
	}
	return path;
}

static void disconnect(private_ovs_ctl_t *this)
{
	if (this->fd >= 0)
	{
		close(this->fd);
		this->fd = -1;
	}
}

static bool do_connect(private_ovs_ctl_t *this)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct timeval tv = { .tv_sec = OVS_CTL_TIMEOUT };
	char *path;

	path = get_socket_path(this);
	if (!path)
	{
		return FALSE;
	}
	if (strlen(path) >= sizeof(addr.sun_path))
	{
		DBG1(DBG_KNL, "kernel-ovs: socket path too long: %s", path);
		free(path);
		return FALSE;
	}
	strcpy(addr.sun_path, path);

	this->fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (this->fd < 0 ||
		setsockopt(this->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) ||
		setsockopt(this->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) ||
		connect(this->fd, (struct sockaddr*)&addr, sizeof(addr)))
	{
		DBG1(DBG_KNL, "kernel-ovs: unable to connect to %s: %s", path,
			 strerror(errno));
		disconnect(this);
		free(path);
		return FALSE;
	}
	this->generation++;
	DBG1(DBG_KNL, "kernel-ovs: connected to ovs-vswitchd at %s", path);
	free(path);
	return TRUE;
}

/**
 * Growable string buffer
 */
typedef struct {
	char *buf;
	size_t len;
	size_t size;
} strbuf_t;

static void strbuf_reserve(strbuf_t *b, size_t n)
{
	if (b->len + n + 1 > b->size)
	{
		b->size = (b->len + n + 1) * 2;
		b->buf = realloc(b->buf, b->size);
	}
}

static void strbuf_add(strbuf_t *b, const char *s)
{
	size_t n = strlen(s);

	strbuf_reserve(b, n);
	memcpy(b->buf + b->len, s, n + 1);
	b->len += n;
}

/**
 * Append 's' to 'b' as a quoted JSON string
 */
static void strbuf_add_json(strbuf_t *b, const char *s)
{
	strbuf_add(b, "\"");
	for (; *s; s++)
	{
		char esc[8];

		if (*s == '"' || *s == '\\')
		{
			snprintf(esc, sizeof(esc), "\\%c", *s);
		}
		else if ((unsigned char)*s < 0x20)
		{
			snprintf(esc, sizeof(esc), "\\u%04x", (unsigned char)*s);
		}
		else
		{
			esc[0] = *s;
			esc[1] = '\0';
		}
		strbuf_add(b, esc);
	}
	strbuf_add(b, "\"");
}

static bool send_all(int fd, const char *buf, size_t len)
{
	while (len)
	{
		ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);

		if (n <= 0)
		{
			return FALSE;
		}
		buf += n;
		len -= n;
	}
	return TRUE;
}

/**
 * Receive one JSON object
 */
static char *recv_object(int fd)
{
	size_t len = 0, size = 4096;
	char *buf = malloc(size);
	bool in_string = FALSE, escape = FALSE;
	int depth = 0;

	while (TRUE)
	{
		char c;
		ssize_t n = recv(fd, &c, 1, 0);

		if (n <= 0)
		{
			free(buf);
			return NULL;
		}
		if (len + 2 > size)
		{
			size *= 2;
			buf = realloc(buf, size);
		}
		buf[len++] = c;

		if (in_string)
		{
			if (escape)
			{
				escape = FALSE;
			}
			else if (c == '\\')
			{
				escape = TRUE;
			}
			else if (c == '"')
			{
				in_string = FALSE;
			}
		}
		else if (c == '"')
		{
			in_string = TRUE;
		}
		else if (c == '{' || c == '[')
		{
			depth++;
		}
		else if ((c == '}' || c == ']') && --depth == 0)
		{
			buf[len] = '\0';
			return buf;
		}
	}
}

/**
 * Parse the JSON string at 'p', which points to its opening quote, into an
 * allocated C string.  Only ASCII \u escapes are supported.
 */
static char *parse_string(const char **p)
{
	const char *s = *p + 1;
	char *out = malloc(strlen(s) + 1), *o = out;

	while (*s && *s != '"')
	{
		if (*s == '\\' && s[1])
		{
			s++;
			switch (*s)
			{
				case 'n':
					*o++ = '\n';
					break;
				case 't':
					*o++ = '\t';
					break;
				case 'r':
					*o++ = '\r';
					break;
				case 'u':
				{
					u_int code;

					if (sscanf(s + 1, "%4x", &code) == 1)
					{
						*o++ = code < 0x80 ? code : '?';
						s += 4;
					}
					break;
				}
				default:
					*o++ = *s;
					break;
			}
			s++;
		}
		else
		{
			*o++ = *s++;
		}
	}
	*o = '\0';
	*p = *s ? s + 1 : s;
	return out;
}

/**
 * Get the string member 'key' of the top-level JSON object 'json'.  Returns
 * NULL if it is missing or not a string.
 */
static char *get_member(const char *json, const char *key)
{
	const char *p = json;
	int depth = 0;

	while (*p)
	{
		if (*p == '"')
		{
			char *name = parse_string(&p);
			bool match = depth == 1 && streq(name, key);

			free(name);
			while (*p == ' ')
			{
				p++;
			}
			if (match && *p == ':')
			{
				p++;
				while (*p == ' ')
				{
					p++;
				}
				return *p == '"' ? parse_string(&p) : NULL;
			}
			continue;
		}
		if (*p == '{' || *p == '[')
		{
			depth++;
		}
		else if (*p == '}' || *p == ']')
		{
			depth--;
		}
		p++;
	}
	return NULL;
}

/**
 * Send a request and receive its reply, with the mutex held
 */
static char *transact(private_ovs_ctl_t *this, const char *request)
{
	char *response;

	for (int attempt = 0; attempt < 2; attempt++)
	{
		if (this->fd < 0 && !do_connect(this))
		{
			return NULL;
		}
		if (send_all(this->fd, request, strlen(request)))
		{
			response = recv_object(this->fd);
			if (response)
			{
				return response;
			}
		}
		/* ovs-vswitchd may have restarted, try again on a new connection */
		disconnect(this);
	}
	return NULL;
}

METHOD(ovs_ctl_t, call, bool,
	private_ovs_ctl_t *this, char **reply, const char *method, ...)
{
	strbuf_t request = {};
	char *response, *error, id[32];
	const char *arg;
	bool first = TRUE, success = FALSE;
	va_list args;

	*reply = NULL;

	snprintf(id, sizeof(id), "%u", this->next_id++);
	strbuf_add(&request, "{\"id\":");
	strbuf_add(&request, id);
	strbuf_add(&request, ",\"method\":");
	strbuf_add_json(&request, method);
	strbuf_add(&request, ",\"params\":[");
	va_start(args, method);
	while ((arg = va_arg(args, const char*)))
	{
		if (!first)
		{
			strbuf_add(&request, ",");
		}
		strbuf_add_json(&request, arg);
		first = FALSE;
	}
	va_end(args);
	strbuf_add(&request, "]}");

	this->mutex->lock(this->mutex);
	response = transact(this, request.buf);
	this->mutex->unlock(this->mutex);

	/* The request may contain keys */
	memwipe(request.buf, request.size);
	free(request.buf);

	if (!response)
	{
		*reply = strdup("no connection to ovs-vswitchd");
		return FALSE;
	}
	error = get_member(response, "error");
	if (error)
	{
		*reply = error;
	}
	else
	{
		*reply = get_member(response, "result");
		success = TRUE;
	}
	free(response);
	return success;
}

METHOD(ovs_ctl_t, get_generation, u_int,
	private_ovs_ctl_t *this)
{
	u_int generation;

	this->mutex->lock(this->mutex);
	generation = this->generation;
	this->mutex->unlock(this->mutex);
	return generation;
}

METHOD(ovs_ctl_t, destroy, void,
	private_ovs_ctl_t *this)
{
	disconnect(this);
	this->mutex->destroy(this->mutex);
	free(this->socket);
	free(this->rundir);
	free(this);
}

/*
 * Described in header.
 */
ovs_ctl_t *ovs_ctl_create()
{
	private_ovs_ctl_t *this;
	char *socket;

	socket = lib->settings->get_str(lib->settings,
							"%s.plugins.kernel-ovs.socket", NULL, lib->ns);
	INIT(this,
		.public = {
			.call = _call,
			.get_generation = _get_generation,
			.destroy = _destroy,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.fd = -1,
		.next_id = 1,
		.socket = socket ? strdup(socket) : NULL,
		.rundir = strdup(lib->settings->get_str(lib->settings,
							"%s.plugins.kernel-ovs.rundir",
							"/var/run/openvswitch", lib->ns)),
	);
	return &this->public;
}
