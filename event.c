/*
 * This file is part of mtrace.
 * Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
 *  This file is based on the ltrace source
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

#define	_GNU_SOURCE

#include <assert.h>
#include <sys/ptrace.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>

#include "backend.h"
#include "breakpoint.h"
#include "common.h"
#include "debug.h"
#include "event.h"
#include "library.h"
#include "mtrace.h"
#include "options.h"
#include "report.h"
#include "task.h"
#include "trace.h"

static LIST_HEAD(event_head);

void queue_event(struct task *task)
{
	if (task) {
		if (task->event.type != EVENT_NONE)
			list_add_tail(&task->event.list, &event_head);
	}
}

struct task *next_event(void)
{
	if (!list_empty(&event_head)) {
		struct task *task = container_of(event_head.next, struct task, event.list);

		list_del(&task->event.list);

		return task;
	}

	return wait_event();
}

void remove_event(struct task *task)
{
	task->event.type = EVENT_NONE;
	list_del(&task->event.list);
}

void init_event(struct task *task)
{
	task->event.type = EVENT_NONE;
	INIT_LIST_HEAD(&task->event.list);
}

static void show_clone(struct task *task, enum event_type type)
{
	const char *str;

	switch(type) {
	case EVENT_FORK:
		str = "fork";
		break;
	case EVENT_VFORK:
		str = "vfork";
		break;
	case EVENT_CLONE:
		str = "clone";
		break;
	default:
		str = "?";
		break;
	}
	fprintf(stderr, "+++ process pid=%d %s (newpid=%d) +++\n", task->pid, str, task->event.e_un.newpid);
}

static void handle_clone(struct task *task, enum event_type type)
{
	struct task *newtask;
	int newpid = task->event.e_un.newpid;

	debug(DEBUG_FUNCTION, "pid=%d, newpid=%d", task->pid, newpid);

	if (options.verbose)
		show_clone(task, type);

	continue_task(task, 0);

	newtask = pid2task(newpid);
	if (!newtask)
		goto fail;

	if (newtask->leader == newtask) {
		if (task_fork(task, newtask) < 0)
			goto fail;

		if (!options.follow) {
			remove_proc(newtask);
			return;
		}

		report_fork(newtask, task);
	}
	else {
		if (task_clone(task, newtask) < 0)
			goto fail;
	}

	continue_task(newtask, newtask->event.e_un.signum);

	return;
fail:
	fprintf(stderr,
		"Error during init of tracing process %d\n"
		"This process won't be traced.\n",
		newpid
	);
}

static void handle_signal(struct task *task)
{
	if (options.verbose > 1) {
		if (task->event.e_un.signum && (task->event.e_un.signum != SIGSTOP || !task->was_stopped))
			fprintf(stderr, "+++ process pid=%d signal %d: %s +++\n", task->pid, task->event.e_un.signum, strsignal(task->event.e_un.signum));
	}

	continue_task(task, task->event.e_un.signum);
}

static void show_exit(struct task *task)
{
	if (options.verbose)
		fprintf(stderr, "+++ process pid=%d exited (status=%d) +++\n", task->pid, task->event.e_un.ret_val);

}

static void handle_about_exit(struct task *task)
{
	if (task->leader == task) {
		if (report_about_exit(task) != -1) {
			task->about_exit = 1;
			return;
		}
	}
	continue_task(task, 0);
}

static void handle_exit(struct task *task)
{
	show_exit(task);

	if (task->leader == task) {
		report_exit(task);
		remove_proc(task);
	}
	else {
		remove_task(task);
	}
}

static void handle_exit_signal(struct task *task)
{
	if (options.verbose)
		fprintf(stderr, "+++ process pid=%d killed by signal %s (%d) +++\n", task->pid, strsignal(task->event.e_un.signum), task->event.e_un.signum);

	if (task->leader == task) {
		report_exit(task);
		remove_proc(task);
	}
	else {
		remove_task(task);
	}
}

static void handle_exec(struct task *task)
{
	debug(DEBUG_FUNCTION, "pid=%d", task->pid);

	if (!options.follow_exec)
		goto nofollow;

	if (process_exec(task) < 0) {
		fprintf(stderr, "couldn't reinitialize process %d after exec\n", task->pid);
		goto untrace;
	}

	if (options.verbose)
		fprintf(stderr, "+++ process pid=%d exec (%s) +++\n", task->pid, library_execname(task));

	continue_task(task, 0);
	return;
nofollow:
	report_nofollow(task);
untrace:
	remove_proc(task);
}

static int handle_call_after(struct task *task, struct breakpoint *bp)
{
	if (!task->breakpoint)
		return 0;

	task->libsym->func->report_out(task, task->libsym);

	task->breakpoint = NULL;
	task->libsym = NULL;

	return 0;
}

static void handle_breakpoint(struct task *task)
{
	struct breakpoint *bp = task->event.e_un.breakpoint;
	
	debug(DEBUG_FUNCTION, "pid=%d, addr=%#lx", task->pid, bp->addr);

#if HW_BREAKPOINTS > 1
	if (bp->type >= BP_HW) {
		if (++bp->hwcnt >= (BP_REORDER_THRESHOLD << bp->hw))
			reorder_hw_bp(task);
	}
#endif

	if (options.verbose)
		++bp->count;

	if (bp->deleted) {
		struct breakpoint *nbp = breakpoint_find(task, bp->addr);

		if (!nbp)
			nbp = bp;

		skip_breakpoint(task, nbp);
		goto end;
	}

	if (task->skip_bp == bp) {
		breakpoint_put(task->skip_bp);
		task->skip_bp = NULL;
		skip_breakpoint(task, bp);
		goto end;
	}

	if (breakpoint_on_hit(task, bp)) {
		continue_task(task, 0);
		goto end;
	}

	if (bp->libsym && !task->breakpoint) {
		struct library_symbol *libsym = bp->libsym;

		save_param_context(task);

		if (libsym->func->report_out) {
			task->breakpoint = breakpoint_insert(task, get_return_addr(task), NULL, BP_HW_SCRATCH);
			if (task->breakpoint) {
				task->libsym = libsym;
				task->breakpoint->on_hit = handle_call_after;

				enable_scratch_hw_bp(task, task->breakpoint);
			}
		}

		if (libsym->func->report_in)
			libsym->func->report_in(task, libsym);
	}

	if (task->stopped)
		skip_breakpoint(task, bp);

end:
	breakpoint_put(bp);
}

int handle_event(void)
{
	struct task *task = next_event();

	if (!task)
		return 0;

	struct event *event = &task->event;
	enum event_type type = event->type;

	event->type = EVENT_NONE;
	debug(DEBUG_FUNCTION, "pid=%d, type=%d", task->pid, event->type);

	switch (type) {
	case EVENT_NONE:
		debug(DEBUG_EVENT_HANDLER, "pid=%d, event none", task->pid);
		break;
	case EVENT_SIGNAL:
		debug(DEBUG_EVENT_HANDLER, "pid=%d, event signal %d", task->pid, event->e_un.signum);
		handle_signal(task);
		break;
	case EVENT_ABOUT_EXIT:
		debug(DEBUG_EVENT_HANDLER, "pid=%d, event exit %d", task->pid, event->e_un.ret_val);
		handle_about_exit(task);
		break;
	case EVENT_EXIT:
		debug(DEBUG_EVENT_HANDLER, "pid=%d, event exit %d", task->pid, event->e_un.ret_val);
		handle_exit(task);
		break;
	case EVENT_EXIT_SIGNAL:
		debug(DEBUG_EVENT_HANDLER, "pid=%d, event exit signal %d", task->pid, event->e_un.signum);
		handle_exit_signal(task);
		break;
	case EVENT_FORK:
	case EVENT_VFORK:
	case EVENT_CLONE:
		debug(DEBUG_EVENT_HANDLER, "pid=%d, event clone (%u)", task->pid, event->e_un.newpid);
		handle_clone(task, type);
		break;
	case EVENT_EXEC:
		debug(DEBUG_EVENT_HANDLER, "pid=%d, event exec()", task->pid);
		handle_exec(task);
		break;
	case EVENT_BREAKPOINT:
		debug(DEBUG_EVENT_HANDLER, "pid=%d, event breakpoint %#lx", task->pid, event->e_un.breakpoint->addr);
		handle_breakpoint(task);
		break;
	default:
		fprintf(stderr, "Error! unknown event?\n");
		return -1;
	}

	return 1;
}

