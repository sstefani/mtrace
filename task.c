/*
 * This file is part of mtrace.
 * Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
 *  This file is based on the ltrace source
 *   Copyright (C) 2011,2012 Petr Machata, Red Hat Inc.
 *   Copyright (C) 2010 Joe Damato
 *   Copyright (C) 1998,2009 Juan Cespedes
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

#include <sys/types.h>
#include <assert.h>
#include <errno.h>
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
#include "task.h"
#include "trace.h"

static LIST_HEAD(list_of_leaders);

static struct rb_root pid_tree = RB_ROOT;

#ifndef OS_HAVE_PROCESS_DATA
static inline int os_task_init(struct task *task)
{
	return 0;
}

static inline void os_task_destroy(struct task *task)
{
}

static inline int os_task_clone(struct task *retp, struct task *task)
{
	return 0;
}
#endif

#ifndef ARCH_HAVE_PROCESS_DATA
static inline int arch_task_init(struct task *task)
{
	return 0;
}

static inline void arch_task_destroy(struct task *task)
{
}

static inline int arch_task_clone(struct task *retp, struct task *task)
{
	return 0;
}
#endif

struct task *pid2task(pid_t pid)
{
	struct rb_node **new = &(pid_tree.rb_node);

	/* Figure out where to put new node */
	while (*new) {
		struct task *this = container_of(*new, struct task, pid_node);

		if (this->pid == pid)
			return this;

		if (this->pid < pid)
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
	}

	return NULL;
}

static void insert_pid(struct task *task)
{
	struct rb_node **new = &(pid_tree.rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct task *this = container_of(*new, struct task, pid_node);

		parent = *new;

		if (this->pid < task->pid)
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&task->pid_node, parent, new);
	rb_insert_color(&task->pid_node, &pid_tree);
}

static int leader_setup(struct task *leader)
{
	if (!elf_read_main_binary(leader))
		return -1;

	return backtrace_init(leader);
}

static int task_init(struct task *task, int attached)
{
	pid_t tgid;

	/* Add process so that we know who the leader is.  */
	tgid = process_leader(task->pid);
	if (!tgid){
		fprintf(stderr, "%s no tgid for pid=%d\n", __FUNCTION__, task->pid);
		return -1;
	}

	if (tgid == task->pid) {
		task->leader = task;
		task->threads = 1;

		breakpoint_setup(task);

		list_add_tail(&task->leader_list, &list_of_leaders);
	}
	else {
		task->leader = pid2task(tgid);

		if (!task->leader) {
			fprintf(stderr, "%s no leader for tgpid=%d\n", __FUNCTION__, tgid);
			return -1;
		}

		task->leader->threads++;
		task->breakpoints = NULL;
		task->is_64bit = task->leader->is_64bit;

		list_add_tail(&task->task_list, &task->leader->task_list);
	}

	task->attached = attached;

	if (arch_task_init(task) < 0)
		return -1;

	if (os_task_init(task) < 0)
		return -1;

	return 0;
}

static void leader_cleanup(struct task *task)
{
	assert(task->leader);

	task->leader->threads--;
	
	if (task->leader == task) {
		if (task->breakpoint) {
			breakpoint_delete(task, task->breakpoint);
			task->breakpoint = NULL;
		}

		library_clear_all(task);
		breakpoint_clear_all(task);

		list_del(&task->leader_list);
	}
}

static void task_destroy(struct task *task)
{
	backtrace_destroy(task);
	arch_task_destroy(task);
	os_task_destroy(task);
	leader_cleanup(task);
	detach_task(task);
	list_del(&task->task_list);
	rb_erase(&task->pid_node, &pid_tree);
	free(task);
}

struct task *task_new(pid_t pid, int traced)
{
	struct task *task = malloc(sizeof(*task));

	if (!task)
		return NULL;

	memset(task, 0, sizeof(*task));

	task->pid = pid;
	task->traced = traced;
	task->stopped = traced;
	task->was_stopped = 0;

	INIT_LIST_HEAD(&task->task_list);
	INIT_LIST_HEAD(&task->leader_list);

	library_setup(task);

	if (task_init(task, 1) < 0)
		goto fail1;

	init_event(task);

	insert_pid(task);

	return task;
fail1:
	task_destroy(task);
	return NULL;
}

int process_exec(struct task *task)
{
	assert(task->leader == task);

	task->threads_stopped--;

	breakpoint_hw_destroy(task);
	backtrace_destroy(task);
	os_task_destroy(task);
	arch_task_destroy(task);
	leader_cleanup(task);

	if (task_init(task, 0) < 0)
		return -1;

	assert(task->leader == task);

	task->threads_stopped++;

	if (leader_setup(task) < 0)
		return -1;

	return 0;
}

struct task *task_create(const char *command, char **argv)
{
	struct task *task;
	pid_t pid;

	debug(DEBUG_FUNCTION, "`%s'", options.command);

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return NULL;
	}

	if (!pid) { /* child */
		change_uid(options.command);
		trace_me();
		execvp(options.command, argv);
		fprintf(stderr, "Can't execute `%s': %s\n", options.command, strerror(errno));
		_exit(EXIT_FAILURE);
	}

	task = task_new(pid, 0);
	if (!task)
		goto fail2;

	if (trace_wait(task))
		goto fail1;

	if (trace_set_options(task) < 0)
		goto fail2;

	if (leader_setup(task) < 0)
		goto fail1;

	return task;
fail2:
	fprintf(stderr, "failed to initialize process %d\n", pid);
fail1:
	if (task)
		remove_proc(task);
	kill(pid, SIGKILL);
	return NULL;
}

int task_clone(struct task *task, struct task *newtask)
{
	assert(newtask->leader != newtask);
	assert(newtask->event.type == EVENT_SIGNAL);
	assert(newtask->event.e_un.signum == 0);
	assert(newtask->traced);
	assert(newtask->stopped);
	assert(newtask->backtrace == NULL);

	if (backtrace_init(newtask) < 0)
		goto fail;

	breakpoint_hw_clone(newtask);

	return 0;
fail:
	fprintf(stderr, "failed to clone process %d->%d : %s\n", task->pid, newtask->pid, strerror(errno));
	task_destroy(newtask);

	return -1;
}

int task_fork(struct task *task, struct task *newtask)
{
	struct task *leader = task->leader;

	assert(newtask->leader == newtask);
	assert(newtask->event.type == EVENT_SIGNAL);
	assert(newtask->event.e_un.signum == 0);
	assert(newtask->traced);
	assert(newtask->stopped);
	assert(newtask->backtrace == NULL);

	if (backtrace_init(newtask) < 0)
		goto fail;

	if (library_clone_all(newtask, leader))
		goto fail;

	if (breakpoint_clone_all(newtask, leader))
		goto fail;

	newtask->libsym = task->libsym;
	newtask->context = task->context;
	newtask->breakpoint = task->breakpoint;

	if (task->breakpoint)
		newtask->breakpoint = breakpoint_find(newtask, newtask->breakpoint->addr);

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

static struct task *open_one_pid(pid_t pid)
{
	struct task *task;

	debug(DEBUG_PROCESS, "pid=%d", pid);

	task = task_new(pid, 0);
	if (task == NULL)
		goto fail1;

	if (trace_attach(task) < 0)
		goto fail2;

	if (trace_set_options(task) < 0)
		goto fail2;

	return task;
fail2:
	remove_task(task);
fail1:
	return NULL;
}

static void show_attached(struct task *task, void *data)
{
	fprintf(options.output, "+++ process pid=%d attached (%s) +++\n", task->pid, library_execname(task->leader));
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

	if (leader_setup(leader) < 0)
		goto fail1;

	list_for_each(it, &leader->task_list) {
		struct task *task = container_of(it, struct task, task_list);

		task->is_64bit = leader->is_64bit;

		if (backtrace_init(task) < 0) {
			fprintf(stderr, "Cannot init backtrace for pid %d: %s\n", pid, strerror(errno));
			goto fail1;
		}
	};

	if (options.verbose)
		each_task(leader, &show_attached, NULL);

	return;
fail2:
	fprintf(stderr, "Cannot attach to pid %d: %s\n", pid, strerror(errno));
fail1:
	if (leader)
		remove_proc(leader);
}

struct task *get_first_process(void)
{
	if (list_empty(&list_of_leaders))
		return NULL;

	return container_of(list_of_leaders.next, struct task, leader_list);
}

void each_process(void (*cb)(struct task *task))
{
	struct list_head *it, *next;

	list_for_each_safe(it, next, &list_of_leaders) {
		struct task *task = container_of(it, struct task, leader_list);

		(*cb)(task);
	}
}

void each_task(struct task *leader, void (*cb)(struct task *task, void *data), void *data)
{
	struct list_head *it, *next;

	(*cb)(leader, data);

	list_for_each_safe(it, next, &leader->task_list) {
		struct task *task = container_of(it, struct task, task_list);

		(*cb)(task, data);
	};
}

void remove_task(struct task *task)
{
	debug(DEBUG_FUNCTION, "pid=%d", task->pid);

	task_destroy(task);
}

static void clear_leader(struct task *task, void *data)
{
	if (task != data) {
		debug(DEBUG_FUNCTION, "clear pid=%d from leader pid=%d", task->pid, task->leader->pid);

		remove_task(task);
	}
}

void remove_proc(struct task *leader)
{
	debug(DEBUG_FUNCTION, "pid=%d", leader->pid);

	assert(leader->leader == leader);

	breakpoint_disable_all(leader);
	each_task(leader, &clear_leader, leader);
	remove_task(leader);
}

int task_list_empty(void)
{
	return list_empty(&list_of_leaders);
}

void each_pid(void (*cb)(struct task *task))
{
	struct task *task, *next;

	rbtree_postorder_for_each_entry_safe(task, next, &pid_tree, pid_node)
		(*cb)(task);
}

