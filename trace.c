/*
 * This file is part of mtrace.
 * Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
 *
 * This work was sponsored by Rohde & Schwarz GmbH & Co. KG, Munich.
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

int skip_breakpoint(struct task *task, struct breakpoint *bp)
{
	debug(DEBUG_PROCESS, "pid=%d, addr=%#lx", task->pid, bp->addr);

	if (task->event.type != EVENT_NONE)
		return 1;

	if (bp->enabled && bp->type == SW_BP) {
		int ret = 0;

		breakpoint_disable(task, bp);
		ret = do_singlestep(task);
		breakpoint_enable(task, bp);
		if (ret) {
			if (ret == 1) {
				breakpoint_unref(task->skip_bp);
				task->skip_bp = breakpoint_ref(bp);
			}
			return ret;
		}
	}

	continue_task(task, 0);
	return 0;
}

void detach_task(struct task *task)
{
	int sig = 0;

	task_reset_bp(task);

	if (task->event.type == EVENT_SIGNAL)
		sig = task->event.e_un.signum;
	else
	if (task->event.type == EVENT_BREAKPOINT)
		breakpoint_unref(task->event.e_un.breakpoint);

	remove_event(task);
	breakpoint_hw_destroy(task);
	untrace_task(task, sig);
}

static void detach_cb(struct task *task, void *data)
{
	remove_task(task);
}

void detach_proc(struct task *leader)
{
	assert(leader->leader == leader);

	breakpoint_disable_all(leader);
	each_task(leader, &detach_cb, NULL);
}

