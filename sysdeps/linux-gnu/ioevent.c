/*
 * This file is part of mtrace.
 * Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
 *
 * This work was sponsored by Rohde & Schwarz GmbH & Co. KG, Munich/Germany.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"
#include "ioevent.h"

struct io_watch_event {
	int (*func)(void);
};

struct pollfd *io_watch_poll;
struct io_watch_event *io_watch_event;
static unsigned int io_watch_size;
static unsigned int io_watch_elems;

static inline void io_watch_set(unsigned int idx, int fd, int (*func)(void))
{
	io_watch_event[idx].func = func;

	io_watch_poll[idx].fd = fd;
	io_watch_poll[idx].events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;
}

int ioevent_add_input(int fd, int (*func)(void))
{
	unsigned int i;

	for(i = 0; i < io_watch_elems; ++i) {
		if (io_watch_poll[i].fd == fd) {
			io_watch_set(i, fd, func);
			return 1;
		}
	}

	if (io_watch_size == io_watch_elems) {
		io_watch_size += 16;

		io_watch_poll =	realloc(io_watch_poll, sizeof(struct pollfd) * io_watch_size);
		io_watch_event = realloc(io_watch_event, sizeof(struct io_watch_event) * io_watch_size);
	}

	io_watch_set(io_watch_elems, fd, func);

	++io_watch_elems;

	return 0;
}

int ioevent_del_input(int fd)
{
	unsigned int i;

	for(i = 0; i < io_watch_elems; ++i) {
		if (io_watch_poll[i].fd == fd) {
			--io_watch_elems;

			if (i != io_watch_elems) {
				io_watch_set(i,
					io_watch_poll[io_watch_elems].fd,
					io_watch_event[io_watch_elems].func
				);
			}
			return 0;
		}
	}
	return -1;
}

int ioevent_watch(int timeout)
{
	unsigned int i;
	int ret;

	ret = TEMP_FAILURE_RETRY(poll(io_watch_poll, io_watch_elems, timeout));
	if (ret < 0)
		return ret;

	ret = 0;

	for(i = 0; i < io_watch_elems; ++i) {
		if (io_watch_poll[i].revents) {
			if (io_watch_event[i].func() == -1)
				ret = -1;
		}
	}
	return ret;
}


int ioevent_wait_input(int fd, int timeout)
{
	struct pollfd pfd[1];

	pfd[0].fd = fd;
	pfd[0].events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	return TEMP_FAILURE_RETRY(poll(pfd, ARRAY_SIZE(pfd), timeout));
}

