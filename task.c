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

#define _GNU_SOURCE

#include "config.h"

#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "backend.h"
#include "backtrace.h"
#include "breakpoint.h"
#include "common.h"
#include "debug.h"
#include "event.h"
#include "options.h"
#include "library.h"
#include "mtelf.h"
#include "report.h"
#include "server.h"
#include "task.h"
#include "trace.h"

static LIST_HEAD(list_of_leaders);

struct pid_hash *pid_hash[PID_HASH_SIZE];

#ifndef OS_HAVE_PROCESS_DATA
static inline int os_task_init(struct task *task)
{
	(void)task;
	return 0;
}

static inline void os_task_destroy(struct task *task)
{
	(void)task;
}

static inline int os_task_clone(struct task *task, struct task *newtask)
{
	(void)task;
	(void)newtask;
	return 0;
}
#endif

#ifndef ARCH_HAVE_PROCESS_DATA
static inline int arch_task_init(struct task *task)
{
	(void)task;
	return 0;
}

static inline void arch_task_destroy(struct task *task)
{
	(void)task;
}

static inline int arch_task_clone(struct task *task, struct task *newtask)
{
	(void)task;
	(void)newtask;
	return 0;
}
#endif

static inline void delete_pid(struct task *task)
{
	struct pid_hash *entry = pid_hash[PID_HASH(task->pid)];
	unsigned int i;

	for(i = 0; i < entry->num; ++i) {
		struct task **p = &entry->tasks[i];

		if ((*p)->pid == task->pid) {
			entry->num--;
			memmove(p, p + 1, (entry->num - i) * sizeof(entry->tasks[0]));
			break;
		}
	}
}

static inline void insert_pid(struct task *task)
{
	unsigned int pidhash = PID_HASH(task->pid);
	struct pid_hash *entry = pid_hash[pidhash];

	if (!entry) {
		entry = malloc(sizeof(*entry) + 8 * sizeof(entry->tasks[0]));
		entry->num = 0;
		entry->size = 8;

		pid_hash[pidhash] = entry;
	}
	else
	if (entry->size == entry->num) {
		entry->size += 8;
		entry = realloc(entry, sizeof(*entry) + entry->size * sizeof(entry->tasks[0]));

		pid_hash[pidhash] = entry;
	}

	entry->tasks[entry->num++] = task;
}

struct task *pid2task(pid_t pid)
{
	struct pid_hash *entry = pid_hash[PID_HASH(pid)];

	if (!entry)
		return NULL;

	struct task **p = entry->tasks;
	unsigned int n = entry->num;

	while(n) {
		struct task *task = *p;

		if (likely(task->pid == pid))
			return task;

		p++;
		n--;
	}

	return NULL;
}

static void delete_task(struct task *task)
{
	arch_task_destroy(task);
	os_task_destroy(task);
	delete_pid(task);
	breakpoint_clear_all(task);
	free(task);
}

static int leader_setup(struct task *leader, int was_attached)
{
	if (!elf_read_main_binary(leader, was_attached))
		return -1;

	return backtrace_init(leader);
}

static int task_init(struct task *task)
{
	pid_t tgid;
	struct task *leader;

	/* Add process so that we know who the leader is.  */
	tgid = process_leader(task->pid);
	if (!tgid){
		fprintf(stderr, "%s no tgid for pid=%d\n", __FUNCTION__, task->pid);
		return -1;
	}

	if (tgid == task->pid) {
		leader = task;
	}
	else {
		leader = pid2task(tgid);

		if (!leader) {
			fprintf(stderr, "%s no leader for tgpid=%d\n", __FUNCTION__, tgid);
			return -1;
		}
	}

	task->leader = leader;

	if (arch_task_init(task) < 0)
		return -1;

	if (os_task_init(task) < 0)
		return -1;

	if (task == leader) {
		task->threads = 1;

		breakpoint_setup(task);

		list_add_tail(&task->leader_list, &list_of_leaders);
	}
	else {
		leader->threads++;
		task->breakpoints = NULL;

		list_add_tail(&task->task_list, &leader->task_list);
	}

	breakpoint_hw_destroy(task);

	return 0;
}

static void leader_cleanup(struct task *leader)
{
	library_clear_all(leader);
	breakpoint_clear_all(leader);
	backtrace_destroy(leader);

	list_del(&leader->leader_list);
}

static void task_destroy(struct task *task)
{
	struct task *leader = task->leader;

	if (task->deleted)
		return;

	task->deleted = 1;

	stop_task(task);

	if (leader != task)
		list_del(&task->task_list);

	leader->threads--;
	leader->threads_stopped--;

	if (task->event.type == EVENT_BREAKPOINT)
		breakpoint_put(task->event.e_un.breakpoint);

	arch_task_destroy(task);
	os_task_destroy(task);
	task_reset_bp(task);
	breakpoint_hw_destroy(task);
	delete_pid(task);

	if (!leader->threads)
		leader_cleanup(leader);

	untrace_task(task);
	remove_event(task);

	if (leader != task)
		free(task);

	if (!leader->threads)
		free(leader);
}

struct task *task_new(pid_t pid)
{
	struct task *task = malloc(sizeof(*task));

	if (!task)
		return NULL;

	memset(task, 0, sizeof(*task));

	task->pid = pid;
	task->attached = 0;
	task->stopped = 0;
	task->bp_skipped = 0;
	task->is_new = 1;
	task->defer_func = NULL;
	task->defer_data = NULL;

	INIT_LIST_HEAD(&task->task_list);
	INIT_LIST_HEAD(&task->leader_list);
#if HW_BREAKPOINTS > 1
	INIT_LIST_HEAD(&task->hw_bp_list);
#endif
	library_setup(task);

	init_event(task);

	if (task_init(task) < 0)
		goto fail1;

	insert_pid(task);

	return task;
fail1:
	free(task);

	return NULL;
}

static void remove_task_cb(struct task *task, void *data)
{
	if (task != data) {
		debug(DEBUG_FUNCTION, "clear pid=%d from leader pid=%d", task->pid, task->leader->pid);

		task_destroy(task);
	}
}

int process_exec(struct task *task)
{
	struct task *leader = task->leader;

	breakpoint_invalidate_all(leader);

	each_task(leader, &remove_task_cb, leader);

	assert(leader->threads == 1);

	os_task_destroy(leader);
	arch_task_destroy(leader);
	leader_cleanup(leader);

	if (task_init(leader) < 0)
		goto fail;

	assert(leader->leader == leader);
	assert(leader->threads == 1);
	assert(leader->threads_stopped == 1);

	if (leader_setup(leader, 0) < 0)
		goto fail;

	return 0;
fail:
	task_destroy(leader);
	return -1;
}

struct task *task_create(char **argv)
{
	struct task *task;
	pid_t pid;
	int ret;

	pid = fork();
	if (pid == -1) {
		perror("fork");
		return NULL;
	}

	if (!pid) { /* child */
		change_uid();

		trace_me();
		execvp(options.command, argv);
		fprintf(stderr, "Can't execute `%s': %s\n", options.command, strerror(errno));
		_exit(EXIT_FAILURE);
	}

	task = task_new(pid);
	if (!task)
		goto fail1;

	if (trace_wait(task))
		goto fail1;

	if (trace_set_options(task) < 0)
		goto fail1;

	if (leader_setup(task, 0) < 0)
		goto fail2;

	ret = handle_event(task);
	if (ret < 0)
		goto fail2;

	if (ret > 0)
		return NULL;

	return task;
fail1:
	fprintf(stderr, "failed to initialize process %d\n", pid);
	if (task) {
		delete_task(task);
		kill(pid, SIGKILL);
	}
	return NULL;
fail2:
	remove_proc(task);
	return NULL;
}

int task_clone(struct task *task, struct task *newtask)
{
	assert(newtask->attached);
	assert(newtask->leader != newtask);
	assert(newtask->backtrace == NULL);

	newtask->is_64bit = task->is_64bit;

	breakpoint_hw_clone(newtask);

	return 0;
}

int task_fork(struct task *task, struct task *newtask)
{
	struct task *leader = task->leader;

	assert(newtask->leader == newtask);
	assert(newtask->attached);
	assert(newtask->backtrace == NULL);

	newtask->is_64bit = task->is_64bit;

	if (backtrace_init(newtask) < 0)
		goto fail;

	if (library_clone_all(newtask, leader))
		goto fail;

	if (breakpoint_clone_all(newtask, leader))
		goto fail;

	newtask->libsym = task->libsym;
	newtask->context = task->context;
	newtask->attached = task->attached;

	if (task->breakpoint)
		newtask->breakpoint = breakpoint_find(newtask, newtask->breakpoint->addr);
	else
		newtask->breakpoint = NULL;

	if (task->skip_bp && !task->skip_bp->deleted)
		newtask->skip_bp = breakpoint_get(breakpoint_find(newtask, newtask->skip_bp->addr));
	else
		newtask->skip_bp = NULL;

	if (arch_task_clone(newtask, task) < 0)
		goto fail;

	if (os_task_clone(newtask, task) < 0)
		goto fail;

	return 0;
fail:
	fprintf(stderr, "failed to fork process %d->%d : %s\n", task->pid, newtask->pid, strerror(errno));
	task_destroy(newtask);

	return -1;
}

void task_reset_bp(struct task *task)
{
	if (task->skip_bp) {
		breakpoint_put(task->skip_bp);
		task->skip_bp = NULL;
	}

	task->breakpoint = NULL;
}

static struct task *open_one_pid(pid_t pid)
{
	struct task *task;

	debug(DEBUG_PROCESS, "pid=%d", pid);

	task = task_new(pid);
	if (task == NULL)
		goto fail1;

	if (trace_attach(task) < 0)
		goto fail2;

	if (trace_set_options(task) < 0)
		goto fail2;

	queue_event(task);

	return task;
fail2:
	delete_task(task);
	kill(pid, SIGCONT);
fail1:
	return NULL;
}

static void show_attached(struct task *task, void *data)
{
	(void)data;

	fprintf(stderr, "+++ process pid=%d attached (%s)\n", task->pid, library_execname(task->leader));
}


void open_pid(pid_t pid)
{
	struct task *leader;
	struct list_head *it;

	debug(DEBUG_PROCESS, "pid=%d", pid);

	/* If we are already tracing this guy, we should be seeing all
	 * his children via normal tracing route.  */
	if (pid2task(pid) != NULL)
		return;

	/* First, see if we can attach the requested PID itself.  */
	leader = open_one_pid(pid);
	if (!leader)
		goto fail2;

	/* Now attach to all tasks that belong to that PID.  There's a
	 * race between process_tasks and open_one_pid.  So when we
	 * fail in open_one_pid below, we just do another round.
	 * Chances are that by then that PID will have gone away, and
	 * that's why we have seen the failure.  The task_es that we
	 * manage to open_one_pid are stopped, so we should eventually
	 * reach a point where process_tasks doesn't give any new
	 * task_es (because there's nobody left to produce
	 * them).  */
	size_t old_ntasks = 0;
	int have_all;

	for(;;) {
		pid_t *tasks;
		size_t ntasks;
		size_t i;

		if (process_tasks(pid, &tasks, &ntasks) < 0) {
			fprintf(stderr, "Cannot obtain tasks of pid %d: %s\n", pid, strerror(errno));
			goto fail1;
		}

		have_all = 1;
		for (i = 0; i < ntasks; ++i) {
			if (!pid2task(tasks[i])) {
				open_one_pid(tasks[i]);

				have_all = 0;
			}
		}

		free(tasks);

		if (have_all && old_ntasks == ntasks)
			break;
		old_ntasks = ntasks;
	}

	if (leader_setup(leader, 1) < 0)
		goto fail1;

	list_for_each(it, &leader->task_list) {
		struct task *task = container_of(it, struct task, task_list);

		assert(task->leader == leader);

		task->is_64bit = leader->is_64bit;
	};

	if (unlikely(options.verbose))
		each_task(leader, &show_attached, NULL);

	return;
fail2:
	fprintf(stderr, "Cannot attach to pid %d: %s\n", pid, strerror(errno));
fail1:
	if (leader)
		remove_proc(leader);
}

void each_process(void (*cb)(struct task *task))
{
	struct list_head *it, *next;

	for(it = list_of_leaders.prev; it != &list_of_leaders; it = next) {
		next = it->prev;

		struct task *task = container_of(it, struct task, leader_list);

		(*cb)(task);
	}
}

void each_task(struct task *leader, void (*cb)(struct task *task, void *data), void *data)
{
	struct list_head *it, *next;

	list_for_each_safe(it, next, &leader->task_list) {
		struct task *task = container_of(it, struct task, task_list);

		(*cb)(task, data);
	};
	(*cb)(leader, data);
}

void remove_task(struct task *task)
{
	debug(DEBUG_FUNCTION, "pid=%d", task->pid);

	task_destroy(task);
}

void remove_proc(struct task *leader)
{
	debug(DEBUG_FUNCTION, "pid=%d", leader->pid);

	assert(leader->leader == leader);

	stop_threads(leader);
	breakpoint_disable_all(leader);
	each_task(leader, &remove_task_cb, leader);
	assert(leader->threads == 1);
	task_destroy(leader);
}

void untrace_proc(struct task *leader)
{
	debug(DEBUG_FUNCTION, "pid=%d", leader->pid);

	assert(leader->leader == leader);

	breakpoint_invalidate_all(leader);
	remove_proc(leader);
}

int task_list_empty(void)
{
	return list_empty(&list_of_leaders);
}

void each_pid(void (*cb)(struct task *task))
{
	unsigned int i;

	for(i = 0; i < ARRAY_SIZE(pid_hash); ++i) {
		struct pid_hash *entry = pid_hash[i];

		if (entry) {
			unsigned int n = entry->num;

			if (n) {
				struct task **p = alloca(n * sizeof(*p));

				memcpy(p, entry->tasks, n * sizeof(*p));

				do {
					(*cb)(*p++);
				} while(--n);
			}
		}
	}
}

