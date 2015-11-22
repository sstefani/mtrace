/*
 * This file is part of mtrace-ng.
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

#ifndef _INC_BACKTRACE_H
#define _INC_BACKTRACE_H

#include <assert.h>

#include "dwarf.h"
#include "main.h"
#include "options.h"
#include "task.h"
#include "timer.h"

/* init backtrace for given leader task */
static inline int backtrace_init(struct task *task)
{
	assert(task->leader == task);
	assert(task->backtrace == NULL);

	task->backtrace = dwarf_init(task->is_64bit);

	return task->backtrace != NULL;
}

/* destroy backtrace for given leader task */
static inline void backtrace_destroy(struct task *task)
{
	assert(task->leader == task);

	if (task->backtrace) {
		dwarf_destroy(task->backtrace);

		task->backtrace = NULL;
	}
}

/* start backtrace for given task */
static inline int backtrace_init_unwind(struct task *task)
{
	assert(task->leader);
	assert(task->leader->backtrace);

	return dwarf_init_unwind(task->leader->backtrace, task);
}

/* get backtrace IP address for given task */
static inline unsigned long backtrace_get_ip(struct task *task)
{
	assert(task->leader);
	assert(task->leader->backtrace);

	return dwarf_get_ip(task->leader->backtrace);
}

/* step to next backtrace given task */
static inline int backtrace_step(struct task *task)
{
	int ret;
	struct timespec start;

	assert(task->leader);
	assert(task->leader->backtrace);

	if (unlikely(options.verbose > 1))
		start_time(&start);

	ret = dwarf_step(task->leader->backtrace);

	if (unlikely(options.verbose > 1))
		set_timer(&start, &backtrace_time);

	return ret;
}

/* get backtrace location type of given task */
static inline int backtrace_location_type(struct task *task)
{
	assert(task->leader);
	assert(task->leader->backtrace);

	return dwarf_location_type(task->leader->backtrace);
}
#endif

