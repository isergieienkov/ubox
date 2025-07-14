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

#include <linux/un.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <regex.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <ctype.h>

#include <libubox/uloop.h>
#include <libubox/usock.h>
#include <libubox/ustream.h>

#include "syslog.h"

#define LOG_DEFAULT_SIZE	(16 * 1024)
#define LOG_DEFAULT_SOCKET	"/dev/log"
#define SYSLOG_PADDING		16

#define KLOG_DEFAULT_PROC	"/proc/kmsg"

#define PAD(x) (x % 4) ? (((x) - (x % 4)) + 4) : (x)

static char *log_dev = LOG_DEFAULT_SOCKET;
static int log_size = LOG_DEFAULT_SIZE;
static struct log_head *log, *log_end, *oldest, *newest;
static int current_id = 0;
static regex_t pat_prio;
static regex_t pat_tstamp;

/* Rate limiting variables */
static struct rate_limit_entry *rate_limit_table = NULL;
static struct uloop_timeout rate_limit_timer;
int rate_limit_threshold = RATE_LIMIT_THRESHOLD;
int rate_limit_timeframe = RATE_LIMIT_TIMEFRAME;
int rate_limit_report_interval = RATE_LIMIT_REPORT_INTERVAL;

static struct log_head*
log_next(struct log_head *h, int size)
{
	struct log_head *n = (struct log_head *) &h->data[PAD(size)];

	return (n >= log_end) ? (log) : (n);
}

/* Simple hash function for message deduplication */
static void
get_msg_hash(const char *msg, char *hash, size_t hash_size)
{
	unsigned int h = 5381;
	const char *p = msg;

	/* Skip timestamp-like patterns at the beginning */
	while (*p && (*p == '[' || isdigit(*p) || *p == '.' || *p == ']' || isspace(*p)))
		p++;

	while (*p) {
		h = ((h << 5) + h) + *p;
		p++;
	}

	snprintf(hash, hash_size, "%u", h);
}

/* Find or create rate limit entry */
static struct rate_limit_entry*
rate_limit_find_or_create(const char *hash)
{
	struct rate_limit_entry *entry = rate_limit_table;
	struct rate_limit_entry *prev = NULL;
	time_t now = time(NULL);
	char debug_msg[256];

	/* Find existing entry */
	while (entry) {
		if (strcmp(entry->msg_hash, hash) == 0) {
			/* Reset if outside timeframe */
			if (now - entry->first_seen > rate_limit_timeframe) {
				snprintf(debug_msg, sizeof(debug_msg),
					"Rate limit: Resetting hash %s (timeframe expired)", hash);
				log_add(debug_msg, strlen(debug_msg) + 1, SOURCE_INTERNAL);
				entry->count = 0;
				entry->first_seen = now;
			}
			return entry;
		}
		prev = entry;
		entry = entry->next;
	}

	/* Create new entry */
	entry = calloc(1, sizeof(struct rate_limit_entry));
	if (!entry)
		return NULL;

	strncpy(entry->msg_hash, hash, sizeof(entry->msg_hash) - 1);
	entry->first_seen = now;
	entry->count = 0;

	if (prev)
		prev->next = entry;
	else
		rate_limit_table = entry;

	snprintf(debug_msg, sizeof(debug_msg),
		"Rate limit: Created new entry for hash %s", hash);
	log_add(debug_msg, strlen(debug_msg) + 1, SOURCE_INTERNAL);
	return entry;
}

/* Rate limit timer callback */
static void
rate_limit_timer_cb(struct uloop_timeout *timeout)
{
	struct rate_limit_entry *entry = rate_limit_table;
	struct rate_limit_entry *prev = NULL;
	struct rate_limit_entry *next;
	time_t now = time(NULL);
	char buf[256];
	char debug_msg[256];
	int reported = 0;

	log_add("Rate limit: Timer callback triggered",
		strlen("Rate limit: Timer callback triggered") + 1, SOURCE_INTERNAL);

	while (entry) {
		next = entry->next;

		/* Report suppressed messages */
		if (entry->count > rate_limit_threshold) {
			snprintf(buf, sizeof(buf),
				"Rate limit: suppressed %d similar messages in last %d seconds",
				entry->count - rate_limit_threshold, rate_limit_report_interval);

			snprintf(debug_msg, sizeof(debug_msg),
				"Rate limit: Reporting suppression: %s", buf);
			log_add(debug_msg, strlen(debug_msg) + 1, SOURCE_INTERNAL);

			/* Add internal log message */
			struct log_head *saved_newest = newest;
			log_add(buf, strlen(buf) + 1, SOURCE_INTERNAL);
			newest = saved_newest;
			reported++;
		}

		/* Clean up old entries */
		if (now - entry->last_seen > rate_limit_report_interval) {
			snprintf(debug_msg, sizeof(debug_msg),
				"Rate limit: Cleaning up old entry for hash %s", entry->msg_hash);
			log_add(debug_msg, strlen(debug_msg) + 1, SOURCE_INTERNAL);
			if (prev)
				prev->next = next;
			else
				rate_limit_table = next;
			free(entry);
		} else {
			prev = entry;
		}

		entry = next;
	}

	snprintf(debug_msg, sizeof(debug_msg),
		"Rate limit: Timer reported %d suppression messages", reported);
	log_add(debug_msg, strlen(debug_msg) + 1, SOURCE_INTERNAL);

	/* Re-arm timer */
	uloop_timeout_set(&rate_limit_timer, rate_limit_report_interval * 1000);
}

void
log_add(char *buf, int size, int source)
{
	regmatch_t matches[4];
	struct log_head *next;
	int priority = 0;
	int ret;
	char *c;
	char msg_hash[64];
	struct rate_limit_entry *rate_entry;
	int should_log = 1;
	char debug_msg[256];

	/* bounce out if we don't have init'ed yet (regmatch etc will blow) */
	if (!log) {
		fprintf(stderr, "%s", buf);
		return;
	}

	for (c = buf; *c; c++) {
		if (*c == '\n')
		*c = ' ';
	}

	c = buf + size - 2;
	while (isspace(*c)) {
		size--;
		c--;
	}

	buf[size - 1] = 0;

	/* strip the priority */
	ret = regexec(&pat_prio, buf, 3, matches, 0);
	if (!ret) {
		priority = atoi(&buf[matches[1].rm_so]);
		size -= matches[2].rm_so;
		buf += matches[2].rm_so;
	}

#if 0
	/* strip kernel timestamp */
	ret = regexec(&pat_tstamp,buf, 4, matches, 0);
	if ((source == SOURCE_KLOG) && !ret) {
		size -= matches[3].rm_so;
		buf += matches[3].rm_so;
	}
#endif

	/* strip syslog timestamp */
	if ((source == SOURCE_SYSLOG) && (size > SYSLOG_PADDING) && (buf[SYSLOG_PADDING - 1] == ' ')) {
		size -= SYSLOG_PADDING;
		buf += SYSLOG_PADDING;
	}

	/* Rate limiting check */
	if (source != SOURCE_INTERNAL) {
		get_msg_hash(buf, msg_hash, sizeof(msg_hash));
		snprintf(debug_msg, sizeof(debug_msg),
			"Rate limit: Message hash: %s, msg: %.50s...", msg_hash, buf);
		log_add(debug_msg, strlen(debug_msg) + 1, SOURCE_INTERNAL);

		rate_entry = rate_limit_find_or_create(msg_hash);

		if (rate_entry) {
			rate_entry->count++;
			rate_entry->last_seen = time(NULL);

			snprintf(debug_msg, sizeof(debug_msg),
				"Rate limit: Count for hash %s: %d (threshold: %d)",
				msg_hash, rate_entry->count, rate_limit_threshold);
			log_add(debug_msg, strlen(debug_msg) + 1, SOURCE_INTERNAL);

			/* Suppress message if over threshold */
			if (rate_entry->count > rate_limit_threshold) {
				should_log = 0;
				snprintf(debug_msg, sizeof(debug_msg),
					"Rate limit: Suppressing message (count %d > threshold %d)",
					rate_entry->count, rate_limit_threshold);
				log_add(debug_msg, strlen(debug_msg) + 1, SOURCE_INTERNAL);
			}
		}
	}

	if (!should_log)
		return;

	//fprintf(stderr, "-> %d - %s\n", priority, buf);

	/* find new oldest entry */
	next = log_next(newest, size);
	if (next > newest) {
		while ((oldest > newest) && (oldest <= next) && (oldest != log))
			oldest = log_next(oldest, oldest->size);
	} else {
		//fprintf(stderr, "Log wrap\n");
		newest->size = 0;
		next = log_next(log, size);
		for (oldest = log; oldest <= next; oldest = log_next(oldest, oldest->size))
			;
		newest = log;
	}

	/* add the log message */
	newest->size = size;
	newest->id = current_id++;
	newest->priority = priority;
	newest->source = source;
	clock_gettime(CLOCK_REALTIME, &newest->ts);
	strcpy(newest->data, buf);

	ubus_notify_log(newest);

	newest = next;
}

static void
syslog_handle_fd(struct uloop_fd *fd, unsigned int events)
{
	static char buf[LOG_LINE_SIZE];
	int len;

	while (1) {
		len = recv(fd->fd, buf, LOG_LINE_SIZE - 1, 0);
		if (len < 0) {
			if (errno == EINTR)
				continue;

			break;
		}
		if (!len)
			break;

		buf[len] = 0;

		log_add(buf, strlen(buf) + 1, SOURCE_SYSLOG);
	}
}

static void
klog_cb(struct ustream *s, int bytes)
{
	struct ustream_buf *buf = s->r.head;
	char *newline, *str;
	int len;

	do {
		str = ustream_get_read_buf(s, NULL);
		if (!str)
			break;
		newline = strchr(buf->data, '\n');
		if (!newline)
			break;
		*newline = 0;
		len = newline + 1 - str;
		log_add(buf->data, len, SOURCE_KLOG);
		ustream_consume(s, len);
	} while (1);
}

static struct uloop_fd syslog_fd = {
	.cb = syslog_handle_fd
};

static struct ustream_fd klog = {
	.stream.string_data = true,
	.stream.notify_read = klog_cb,
};

static int
klog_open(void)
{
	int fd;

	fd = open(KLOG_DEFAULT_PROC, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s\n", KLOG_DEFAULT_PROC);
		return -1;
	}
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
	ustream_fd_init(&klog, fd);
	return 0;
}

static int
syslog_open(void)
{
	unlink(log_dev);
	syslog_fd.fd = usock(USOCK_UNIX | USOCK_UDP | USOCK_SERVER | USOCK_NONBLOCK, log_dev, NULL);
	if (syslog_fd.fd < 0) {
		fprintf(stderr,"Failed to open %s\n", log_dev);
		return -1;
	}
	chmod(log_dev, 0666);
	uloop_fd_add(&syslog_fd, ULOOP_READ | ULOOP_EDGE_TRIGGER);

	return 0;
}

struct log_head*
log_list(int count, struct log_head *h)
{
	unsigned int min = count;

	if (count)
		min = (count < current_id) ? (current_id - count) : (0);
	if (!h && oldest->id >= min)
		return oldest;
	if (!h)
		h = oldest;

	while (h != newest) {
		h = log_next(h, h->size);
		if (!h->size && (h > newest))
			h = log;
		if (h->id >= min && (h != newest))
			return h;
	}

	return NULL;
}

int
log_buffer_init(int size)
{
	struct log_head *_log = calloc(1, size);

	if (!_log) {
		fprintf(stderr, "Failed to initialize log buffer with size %d\n", log_size);
		return -1;
	}

	if (log && ((log_size + sizeof(struct log_head)) < size)) {
		struct log_head *start = _log;
		struct log_head *end = ((void*) _log) + size;
		struct log_head *l;

		l = log_list(0, NULL);
		while ((start < end) && l && l->size) {
			memcpy(start, l, PAD(sizeof(struct log_head) + l->size));
			start = (struct log_head *) &l->data[PAD(l->size)];
			l = log_list(0, l);
		}
		free(log);
		newest = start;
		newest->size = 0;
		oldest = log = _log;
		log_end = ((void*) log) + size;
	} else {
		oldest = newest = log = _log;
		log_end = ((void*) log) + size;
	}
	log_size = size;

	return 0;
}

void
log_init(int _log_size)
{
	char debug_msg[256];

	if (_log_size > 0)
		log_size = _log_size;

	regcomp(&pat_prio, "^<([0-9]*)>(.*)", REG_EXTENDED);
	regcomp(&pat_tstamp, "^\[[ 0]*([0-9]*).([0-9]*)] (.*)", REG_EXTENDED);

	if (log_buffer_init(log_size)) {
		fprintf(stderr, "Failed to allocate log memory\n");
		exit(-1);
	}

	snprintf(debug_msg, sizeof(debug_msg),
		"Rate limit: Initialized - threshold: %d, timeframe: %d, report_interval: %d",
		rate_limit_threshold, rate_limit_timeframe, rate_limit_report_interval);
	log_add(debug_msg, strlen(debug_msg) + 1, SOURCE_INTERNAL);

	/* Initialize rate limit timer */
	rate_limit_timer.cb = rate_limit_timer_cb;
	uloop_timeout_set(&rate_limit_timer, rate_limit_report_interval * 1000);

	syslog_open();
	klog_open();
	openlog("sysinit", LOG_CONS, LOG_DAEMON);
}

void
rate_limit_cleanup(void)
{
	struct rate_limit_entry *entry = rate_limit_table;
	struct rate_limit_entry *next;

	while (entry) {
		next = entry->next;
		free(entry);
		entry = next;
	}
	rate_limit_table = NULL;
}

void
log_shutdown(void)
{
	if (syslog_fd.registered) {
		uloop_fd_delete(&syslog_fd);
		close(syslog_fd.fd);
	}

	uloop_timeout_cancel(&rate_limit_timer);
	rate_limit_cleanup();

	ustream_free(&klog.stream);
	close(klog.fd.fd);
	free(log);
	regfree(&pat_prio);
	regfree(&pat_tstamp);
}
