/*
 * This file is part of mtrace-ng.
 * Copyright (C) 2018 Stefani Seibold <stefani@seibold.net>
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

#ifndef _INC_TIMER_H
#define _INC_TIMER_H

#include <time.h>
#include <sys/time.h>

struct mt_timer {
	unsigned int max;
	unsigned int count;
	unsigned long long culminate;
};

static inline int start_time(struct timespec *ts)
{
	return clock_gettime(CLOCK_THREAD_CPUTIME_ID, ts);
}

static inline int set_timer(struct timespec *start, struct mt_timer *p)
{ 
	struct timespec now;
	unsigned int usec;

	if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now) == -1)
		return -1;

	usec = (now.tv_sec - start->tv_sec) * 1000000L +
		(now.tv_nsec - start->tv_nsec + 500L) / 1000;

	if (p->max < usec)
		p->max = usec;

	p->culminate += usec;

	++p->count;

	return 0;
}

#endif

