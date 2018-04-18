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
#include "main.h"
#include "mtrace.h"
#include "options.h"
#include "report.h"
#include "task.h"
#include "timer.h"
#include "trace.h"

#define	RET_DELETED	1
#define	RET_DEFERED	2

static LIST_HEAD(event_head);

void queue_event(struct task *task)
{
	assert(task->event.type != EVENT_NONE);
	assert(task->stopped);

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

static const char * get_clone_type(enum event_type type)
{
	switch(type) {
	case EVENT_FORK:
		return "fork";
	case EVENT_VFORK:
		return "vfork";
	case EVENT_CLONE:
		return "clone";
	default:
		break;
	}
	return "?";
}

static int do_clone(struct task *task, struct task *newtask)
{
	debug(DEBUG_EVENT, "+++ process %s pid=%d, newpid=%d", get_clone_type(task->event.type), task->pid, newtask->pid);

	if (unlikely(options.verbose))
		fprintf(stderr, "+++ process %s pid=%d, newpid=%d\n", get_clone_type(task->event.type), task->pid, newtask->pid);

	assert(task->stopped);
	assert(newtask->stopped);
	assert(newtask->is_new);

	if (unlikely(options.verbose && newtask->event.type != EVENT_NEW))
		fprintf(stderr, "!!!task new unexpected event for pid=%d: %d\n", newtask->pid, newtask->event.type);
	else
	if (unlikely(options.verbose && newtask->event.e_un.signum))
		fprintf(stderr, "!!!task new unexpected signal for pid=%d: %d\n", newtask->pid, newtask->event.e_un.signum);

	if (newtask->leader == newtask) {
		if (task_fork(task, newtask) < 0)
			goto fail;

		if (!options.follow) {
			remove_proc(newtask);
			return RET_DELETED;
		}

		report_fork(newtask, task);
	}
	else {
		if (task_clone(task, newtask) < 0)
			goto fail;
	}

	newtask->is_new = 0;
	return continue_task(newtask, 0);
fail:
	fprintf(stderr, "Error during clone of pid=%d - This process won't be traced!\n", newtask->pid);
	return -1;
}

static int do_clone_cb(struct task *newtask, void *data)
{
	int ret;
	struct task *task = data;

	debug(DEBUG_EVENT, "+++ process do clone cb pid=%d, newpid=%d", task->pid, newtask->pid);

	ret = do_clone(task, newtask);
	continue_task(task, 0);
	return ret;
}

static int handle_child(struct task *task)
{
	struct task *newtask;
	int newpid = task->event.e_un.newpid;

	debug(DEBUG_EVENT, "+++ process child pid=%d, newpid=%d", task->pid, newpid);

	newtask = pid2task(newpid);

	assert(newtask != NULL);

	if (!newtask->stopped) {
		debug(DEBUG_EVENT, "+++ process defer child pid=%d, newpid=%d", task->pid, newpid);
		newtask->defer_func = do_clone_cb;
		newtask->defer_data = task;
		return RET_DEFERED;
	}

	do_clone(task, newtask);
	return continue_task(task, 0);
}

static int handle_signal(struct task *task)
{
	debug(DEBUG_EVENT, "+++ process signal pid=%d, event signal %d", task->pid, task->event.e_un.signum);

	if (unlikely(options.verbose > 1)) {
		if (task->event.e_un.signum)
			fprintf(stderr, "+++ process pid=%d signal %d: %s\n", task->pid, task->event.e_un.signum, strsignal(task->event.e_un.signum));
	}

	return continue_task(task, task->event.e_un.signum);
}

static void show_exit(struct task *task)
{
	if (unlikely(options.verbose))
		fprintf(stderr, "+++ process pid=%d exited (status=%d)\n", task->pid, task->event.e_un.ret_val);
}

static int handle_new(struct task *task)
{
	debug(DEBUG_EVENT, "+++ process new pid=%d, event signal %d", task->pid, task->event.e_un.signum);

	assert(task->is_new);

	if (unlikely(options.verbose && task->event.e_un.signum))
		fprintf(stderr, "!!!task unexpected signal for pid=%d: %d\n", task->pid, task->event.e_un.signum);
	task->is_new = 0;

	return continue_task(task, task->event.e_un.signum);
}

static int handle_about_exit(struct task *task)
{
	debug(DEBUG_EVENT, "+++ process pid=%d about exit", task->pid);

	if (task->leader == task) {
		if (!options.logfile && report_about_exit(task) != -1) {
			task->about_exit = 1;
			return 0;
		}
	}
	return continue_task(task, 0);
}

static int handle_exit(struct task *task)
{
	debug(DEBUG_EVENT, "+++ process pid=%d exited (status=%d)", task->pid, task->event.e_un.ret_val);

	show_exit(task);

	if (task->leader == task) {
		report_exit(task);
		untrace_proc(task);
	}
	else {
		remove_task(task);
	}
	return RET_DELETED;
}

static int handle_exit_signal(struct task *task)
{
	debug(DEBUG_EVENT, "+++ process pid=%d killed by signal %s (%d)", task->pid, strsignal(task->event.e_un.signum), task->event.e_un.signum);

	if (unlikely(options.verbose))
		fprintf(stderr, "+++ process pid=%d killed by signal %s (%d)\n", task->pid, strsignal(task->event.e_un.signum), task->event.e_un.signum);

	if (task->leader == task) {
		report_exit(task);
		untrace_proc(task);
	}
	else {
		remove_task(task);
	}
	return RET_DELETED;
}

static int handle_exec(struct task *task)
{
	debug(DEBUG_EVENT, "+++ process pid=%d exec", task->pid);

	if (unlikely(options.verbose))
		fprintf(stderr, "+++ process pid=%d exec\n", task->pid);

	if (!options.follow_exec)
		goto nofollow;

	if (process_exec(task) < 0) {
		fprintf(stderr, "couldn't reinitialize process %d after exec\n", task->pid);
		goto untrace;
	}

	return continue_task(task, 0);
nofollow:
	report_nofollow(task);
untrace:
	untrace_proc(task);
	return RET_DELETED;
}

static int handle_call_after(struct task *task, struct breakpoint *bp)
{
	struct timespec start;

	(void)bp;

	if (!task->breakpoint)
		return 0;

	if (unlikely(options.verbose > 1))
		start_time(&start);

#if HW_BREAKPOINTS > 0
	disable_scratch_hw_bp(task, bp);
#endif

	if (task->libsym->func->report_out)
		task->libsym->func->report_out(task, task->libsym);

	if (unlikely(options.verbose > 1))
		set_timer(&start, &report_out_time);

	task->breakpoint = NULL;
	task->libsym = NULL;

	return 0;
}

static int handle_breakpoint(struct task *task)
{
	struct breakpoint *bp = task->event.e_un.breakpoint;
	unsigned int hw = bp->hw;

	debug(DEBUG_EVENT, "+++ process pid=%d breakpoint  addr=%#lx", task->pid, bp->addr);

	assert(task->stopped);

	if (unlikely(options.verbose > 1))
		set_timer(&task->halt_time, hw ? &hw_bp_time : &sw_bp_time);

	if (unlikely(options.verbose))
		++bp->count;

	if (unlikely(task->skip_bp)) {
		struct breakpoint *skip_bp = task->skip_bp;

		task->skip_bp = NULL;

		breakpoint_put(skip_bp);

		if (likely(skip_bp == bp)) {
			skip_breakpoint(task, bp);
			goto end;
		}

		if (unlikely(options.verbose))
			fprintf(stderr, "!!!unhandled skip breakpoint for pid=%d\n", task->pid);
	}

	if (unlikely(bp->deleted)) {
		continue_task(task, 0);
		goto end;
	}

#if HW_BREAKPOINTS > 1
	if (bp->type >= BP_HW) {
		if (unlikely(++bp->hwcnt >= (BP_REORDER_THRESHOLD << hw))) {
			struct timespec start;

			if (unlikely(options.verbose > 1))
				start_time(&start);

			reorder_hw_bp(task);

			if (unlikely(options.verbose > 1))
				set_timer(&start, &reorder_time);
		}
	}
#endif

	if (bp->on_hit && bp->on_hit(task, bp)) {
		continue_task(task, 0);
		goto end;
	}

	if (likely(bp->libsym && !task->breakpoint)) {
		struct library_symbol *libsym = bp->libsym;

		save_param_context(task);

		if (libsym->func->report_out || !options.nocpp) {
			task->breakpoint = breakpoint_insert(task, get_return_addr(task), NULL, BP_HW_SCRATCH);
			if (likely(task->breakpoint)) {
				task->libsym = libsym;
				task->breakpoint->on_hit = handle_call_after;
#if HW_BREAKPOINTS > 0
				enable_scratch_hw_bp(task, task->breakpoint);
#endif
			}
		}

		if (libsym->func->report_in) {
			struct timespec start;

			if (unlikely(options.verbose > 1))
				start_time(&start);

			libsym->func->report_in(task, libsym);

			if (unlikely(options.verbose > 1))
				set_timer(&start, &report_in_time);
		}
	}

	if (task->bp_skipped)
		task->bp_skipped = 0;
	else
		skip_breakpoint(task, bp);
end:
	breakpoint_put(bp);
	return 0;
}

int handle_event(struct task *task)
{
	int ret;

	if (!task)
		return 0;

	debug(DEBUG_EVENT, "+++ process pid=%d event: %d", task->pid, task->event.type);

	assert(task->stopped);

	if (task->defer_func) {
		ret = task->defer_func(task, task->defer_data);

		if (ret == RET_DELETED)
			return 1;

		task->defer_func = NULL;
		task->defer_data = NULL;
		goto out2;
	}

	struct event *event = &task->event;
	enum event_type type = event->type;

	switch (type) {
	case EVENT_NONE:
		ret = continue_task(task, task->event.e_un.signum);
		break;
	case EVENT_SIGNAL:
		ret = handle_signal(task);
		break;
	case EVENT_ABOUT_EXIT:
		ret = handle_about_exit(task);
		goto out1;
	case EVENT_EXIT:
		ret = handle_exit(task);
		break;
	case EVENT_EXIT_SIGNAL:
		ret = handle_exit_signal(task);
		break;
	case EVENT_FORK:
	case EVENT_VFORK:
	case EVENT_CLONE:
		ret = handle_child(task);
		break;
	case EVENT_EXEC:
		ret = handle_exec(task);
		break;
	case EVENT_BREAKPOINT:
		ret = handle_breakpoint(task);
		goto out2;
	case EVENT_NEW:
		ret = handle_new(task);
		break;
	default:
		fprintf(stderr, "fatal error, unknown event %d\n", type);
		abort();
	}

	if (ret == RET_DELETED)
		return 1;

	if (ret != RET_DEFERED) {
		assert(task->event.type == EVENT_NONE);
		assert(task->stopped == 0);
	}
out2:
	assert(task->is_new == 0);
out1:
	return (ret < 0) ? ret : 0;
}

