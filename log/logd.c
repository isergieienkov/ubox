/*
 * Copyright (C) 2013 John Crispin <blogic@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <sys/types.h>
#include <pwd.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <unistd.h>

#include <linux/types.h>

#include <libubox/uloop.h>
#include <libubox/blobmsg.h>
#include <libubox/list.h>
#include <libubox/ustream.h>
#include <libubus.h>

#include "syslog.h"

int debug = 0;
static struct blob_buf b;
static struct ubus_auto_conn conn;
static LIST_HEAD(clients);

enum {
	READ_LINES,
	READ_STREAM,
	READ_ONESHOT,
	__READ_MAX
};

static const struct blobmsg_policy read_policy[__READ_MAX] = {
	[READ_LINES] = { .name = "lines", .type = BLOBMSG_TYPE_INT32 },
	[READ_STREAM] = { .name = "stream", .type = BLOBMSG_TYPE_BOOL },
	[READ_ONESHOT] = { .name = "oneshot", .type = BLOBMSG_TYPE_BOOL },
};

static const struct blobmsg_policy write_policy =
	{ .name = "event", .type = BLOBMSG_TYPE_STRING };

enum {
	RATE_THRESHOLD,
	RATE_TIMEFRAME,
	RATE_REPORT_INTERVAL,
	__RATE_MAX
};

static const struct blobmsg_policy rate_policy[__RATE_MAX] = {
	[RATE_THRESHOLD] = { .name = "threshold", .type = BLOBMSG_TYPE_INT32 },
	[RATE_TIMEFRAME] = { .name = "timeframe", .type = BLOBMSG_TYPE_INT32 },
	[RATE_REPORT_INTERVAL] = { .name = "report_interval", .type = BLOBMSG_TYPE_INT32 },
};

struct client {
	struct list_head list;

	struct ustream_fd s;
	int fd;
};

static void
client_close(struct ustream *s)
{
	struct client *cl = container_of(s, struct client, s.stream);

	list_del(&cl->list);
	ustream_free(s);
	close(cl->fd);
	free(cl);
}

static void client_notify_state(struct ustream *s)
{
	client_close(s);
}

static void client_notify_write(struct ustream *s, int bytes)
{
	if (ustream_pending_data(s, true))
		return;

	client_close(s);
}

static void
log_fill_msg(struct blob_buf *b, struct log_head *l)
{
	blobmsg_add_string(b, "msg", l->data);
	blobmsg_add_u32(b, "id", l->id);
	blobmsg_add_u32(b, "priority", l->priority);
	blobmsg_add_u32(b, "source", l->source);
	blobmsg_add_u64(b, "time", (((__u64) l->ts.tv_sec) * 1000) + (l->ts.tv_nsec / 1000000));
}

static int
read_log(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct client *cl;
	struct blob_attr *tb[__READ_MAX] = {};
	struct log_head *l;
	int count = 0;
	int fds[2];
	int ret;
	bool stream = true;
	bool oneshot = false;
	void *c, *e;

	if (!stream)
		count = 100;

	if (msg) {
		blobmsg_parse(read_policy, __READ_MAX, tb, blob_data(msg), blob_len(msg));
		if (tb[READ_LINES])
			count = blobmsg_get_u32(tb[READ_LINES]);
		if (tb[READ_STREAM])
			stream = blobmsg_get_bool(tb[READ_STREAM]);
		if (tb[READ_ONESHOT])
			oneshot = blobmsg_get_bool(tb[READ_ONESHOT]);
	}

	l = log_list(count, NULL);
	if (stream) {
		if (pipe(fds) == -1) {
			fprintf(stderr, "logd: failed to create pipe: %m\n");
			return -1;
		}

		ubus_request_set_fd(ctx, req, fds[0]);
		cl = calloc(1, sizeof(*cl));
		cl->s.stream.notify_state = client_notify_state;
		cl->fd = fds[1];
		ustream_fd_init(&cl->s, cl->fd);
		list_add(&cl->list, &clients);
		while ((!tb[READ_LINES] || count) && l) {
			blob_buf_init(&b, 0);
			log_fill_msg(&b, l);
			l = log_list(count, l);
			ret = ustream_write(&cl->s.stream, (void *) b.head, blob_len(b.head) + sizeof(struct blob_attr), false);
			if (ret < 0)
				break;
		}

		if (oneshot) {
			cl->s.stream.notify_write = client_notify_write;
			client_notify_write(&cl->s.stream, 0);
		}
	} else {
		blob_buf_init(&b, 0);
		c = blobmsg_open_array(&b, "log");
		while ((!tb[READ_LINES] || count) && l) {
			e = blobmsg_open_table(&b, NULL);
			log_fill_msg(&b, l);
			blobmsg_close_table(&b, e);
			l = log_list(count, l);
		}
		blobmsg_close_array(&b, c);
		ubus_send_reply(ctx, req, b.head);
	}
	blob_buf_free(&b);
	return 0;
}

static int
write_log(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb;
	char *event;

	if (msg) {
		int len;

		blobmsg_parse(&write_policy, 1, &tb, blob_data(msg), blob_len(msg));
		if (tb) {
			event = blobmsg_get_string(tb);
			len = strlen(event) + 1;
			if (len > LOG_LINE_SIZE) {
				len = LOG_LINE_SIZE;
				event[len - 1] = 0;
			}

			log_add(event, len, SOURCE_SYSLOG);
		}
	}

	return 0;
}

static int
get_rate_limit(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "threshold", rate_limit_threshold);
	blobmsg_add_u32(&b, "timeframe", rate_limit_timeframe);
	blobmsg_add_u32(&b, "report_interval", rate_limit_report_interval);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return 0;
}

static int
set_rate_limit(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[__RATE_MAX] = {};
	bool changed = false;
	char debug_msg[256];

	if (!msg)
		return UBUS_STATUS_INVALID_ARGUMENT;

	blobmsg_parse(rate_policy, __RATE_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[RATE_THRESHOLD]) {
		int val = blobmsg_get_u32(tb[RATE_THRESHOLD]);
		if (val >= 1) {
			snprintf(debug_msg, sizeof(debug_msg),
				"Rate limit: Setting threshold from %d to %d",
				rate_limit_threshold, val);
			log_add(debug_msg, strlen(debug_msg) + 1, SOURCE_INTERNAL);
			rate_limit_threshold = val;
			changed = true;
		}
	}

	if (tb[RATE_TIMEFRAME]) {
		int val = blobmsg_get_u32(tb[RATE_TIMEFRAME]);
		if (val >= 1) {
			snprintf(debug_msg, sizeof(debug_msg),
				"Rate limit: Setting timeframe from %d to %d",
				rate_limit_timeframe, val);
			log_add(debug_msg, strlen(debug_msg) + 1, SOURCE_INTERNAL);
			rate_limit_timeframe = val;
			changed = true;
		}
	}

	if (tb[RATE_REPORT_INTERVAL]) {
		int val = blobmsg_get_u32(tb[RATE_REPORT_INTERVAL]);
		if (val >= 1) {
			snprintf(debug_msg, sizeof(debug_msg),
				"Rate limit: Setting report_interval from %d to %d",
				rate_limit_report_interval, val);
			log_add(debug_msg, strlen(debug_msg) + 1, SOURCE_INTERNAL);
			rate_limit_report_interval = val;
			changed = true;
		}
	}

	if (changed) {
		log_add("Rate limit: Configuration changed, cleaning up table",
			strlen("Rate limit: Configuration changed, cleaning up table") + 1, SOURCE_INTERNAL);
		/* Clean up rate limit table to apply new settings */
		rate_limit_cleanup();
	}

	return 0;
}

static const struct ubus_method log_methods[] = {
	UBUS_METHOD("read", read_log, read_policy),
	{ .name = "write", .handler = write_log, .policy = &write_policy, .n_policy = 1 },
	UBUS_METHOD_NOARG("get_rate_limit", get_rate_limit),
	UBUS_METHOD("set_rate_limit", set_rate_limit, rate_policy),
};

static struct ubus_object_type log_object_type =
	UBUS_OBJECT_TYPE("log", log_methods);

static struct ubus_object log_object = {
	.name = "log",
	.type = &log_object_type,
	.methods = log_methods,
	.n_methods = ARRAY_SIZE(log_methods),
};

void
ubus_notify_log(struct log_head *l)
{
	struct client *c;

	if (list_empty(&clients) && !log_object.has_subscribers)
		return;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "msg", l->data);
	blobmsg_add_u32(&b, "id", l->id);
	blobmsg_add_u32(&b, "priority", l->priority);
	blobmsg_add_u32(&b, "source", l->source);
	blobmsg_add_u64(&b, "time", (((__u64) l->ts.tv_sec) * 1000) + (l->ts.tv_nsec / 1000000));

	if (log_object.has_subscribers)
		ubus_notify(&conn.ctx, &log_object, "message", b.head, -1);

	list_for_each_entry(c, &clients, list)
		ustream_write(&c->s.stream, (void *) b.head, blob_len(b.head) + sizeof(struct blob_attr), false);

	blob_buf_free(&b);
}

static void
ubus_connect_handler(struct ubus_context *ctx)
{
	int ret;

	ret = ubus_add_object(ctx, &log_object);
	if (ret) {
		fprintf(stderr, "Failed to add object: %s\n", ubus_strerror(ret));
		exit(1);
	}
	fprintf(stderr, "log: connected to ubus\n");
}

int
main(int argc, char **argv)
{
	int ch, log_size = 16;
	struct passwd *p = NULL;
	int rate_threshold = RATE_LIMIT_THRESHOLD;
	int rate_timeframe = RATE_LIMIT_TIMEFRAME;
	int rate_report = RATE_LIMIT_REPORT_INTERVAL;
	char debug_msg[256];

	signal(SIGPIPE, SIG_IGN);
	while ((ch = getopt(argc, argv, "S:T:F:R:")) != -1) {
		switch (ch) {
		case 'S':
			log_size = atoi(optarg);
			if (log_size < 1)
				log_size = 16;
			break;
		case 'T':
			rate_limit_threshold = atoi(optarg);
			if (rate_limit_threshold < 1)
				rate_limit_threshold = 10;
			break;
		case 'F':
			rate_limit_timeframe = atoi(optarg);
			if (rate_limit_timeframe < 1)
				rate_limit_timeframe = 5;
			break;
		case 'R':
			rate_limit_report_interval = atoi(optarg);
			if (rate_limit_report_interval < 1)
				rate_limit_report_interval = 10;
			break;
		}
	}
	log_size *= 1024;

	/* Set rate limit parameters before log_init */
	extern int rate_limit_threshold;
	extern int rate_limit_timeframe;
	extern int rate_limit_report_interval;
	rate_limit_threshold = rate_threshold;
	rate_limit_timeframe = rate_timeframe;
	rate_limit_report_interval = rate_report;

	uloop_init();
	log_init(log_size);

	/* Log the initial configuration after log_init */
	snprintf(debug_msg, sizeof(debug_msg),
		"Rate limit: Initialized with threshold=%d, timeframe=%d, report_interval=%d",
		rate_limit_threshold, rate_limit_timeframe, rate_limit_report_interval);
	log_add(debug_msg, strlen(debug_msg) + 1, SOURCE_INTERNAL);

	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);
	p = getpwnam("logd");
	if (p) {
		if (setgid(p->pw_gid) < 0) {
			fprintf(stderr, "setgid() failed: %s\n", strerror(errno));
			exit(1);
		}

		if (setuid(p->pw_uid) < 0) {
			fprintf(stderr, "setuid() failed: %s\n", strerror(errno));
			exit(1);
		}
	}
	uloop_run();
	log_shutdown();
	uloop_done();
	ubus_auto_shutdown(&conn);

	return 0;
}
