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

#include "config.h"

#include <asm/unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "backend.h"
#include "breakpoint.h"
#include "debug.h"
#include "event.h"
#include "options.h"
#include "report.h"
#include "task.h"
#include "library.h"
#include "main.h"

int skip_breakpoint(struct task *task, struct breakpoint *bp)
{
	debug(DEBUG_PROCESS, "pid=%d, addr=%#lx", task->pid, bp->addr);

	assert(task->event.type == EVENT_BREAKPOINT);
	assert(task->stopped);
	assert(task->skip_bp == NULL);

	if (bp->sw && bp->enabled) {
		int ret = 0;
		struct timespec start;

		if (task->skip_bp) {
			task->event.type = EVENT_NONE;
			return 1;
		}

		if (unlikely(options.verbose > 1))
			start_time(&start);

		breakpoint_disable(task, bp);
		ret = do_singlestep(task, bp);
		breakpoint_enable(task, bp);

		if (unlikely(options.verbose > 1))
			set_timer(&start, &skip_bp_time);

		if (unlikely(ret)) {
			task->skip_bp = breakpoint_get(bp);
			assert(task->skip_bp);
			return ret;
		}
	}

	continue_task(task, 0);
	return 0;
}

void fix_about_exit(struct task *task)
{
	if (task->about_exit) {
		task->about_exit = 0;

		continue_task(task, 0);
	}
}

static void detach_cb(struct task *task, void *data)
{
	(void)data;

	remove_task(task);
}

void detach_proc(struct task *leader)
{
	assert(leader->leader == leader);

	breakpoint_disable_all(leader);

	if (unlikely(options.verbose > 1))
		fprintf(stderr, "+++ process detach pid=%d\n", leader->pid);

	each_task(leader, &detach_cb, NULL);
}

