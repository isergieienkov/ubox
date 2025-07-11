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

#ifndef __SYSLOG_H
#define __SYSLOG_H

#define LOG_LINE_SIZE		1024

/* Rate limiting configuration */
#define RATE_LIMIT_THRESHOLD	10	/* messages per timeframe */
#define RATE_LIMIT_TIMEFRAME	5	/* seconds */
#define RATE_LIMIT_REPORT_INTERVAL	10	/* seconds for condensed message */

enum {
	SOURCE_KLOG = 0,
	SOURCE_SYSLOG = 1,
	SOURCE_INTERNAL = 2,
	SOURCE_ANY = 0xff,
};

struct log_head {
	unsigned int size;
	unsigned int id;
	int priority;
	int source;
	struct timespec ts;
	char data[];
};

/* Rate limiting structure */
struct rate_limit_entry {
	char msg_hash[64];	/* simplified hash of message */
	int count;
	time_t first_seen;
	time_t last_seen;
	struct rate_limit_entry *next;
};

/* Rate limiting configuration - extern for access from logd.c */
extern int rate_limit_threshold;
extern int rate_limit_timeframe;
extern int rate_limit_report_interval;

void log_init(int log_size);
void log_shutdown(void);

typedef void (*log_list_cb)(struct log_head *h);
struct log_head* log_list(int count, struct log_head *h);
int log_buffer_init(int size);
void log_add(char *buf, int size, int source);
void ubus_notify_log(struct log_head *l);
void rate_limit_cleanup(void);

#endif
