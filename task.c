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
#include "server.h"
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

static int task_init(struct task *task)
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

		list_add_tail(&task->task_list, &task->leader->task_list);
	}

	task->attached = 1;

	if (arch_task_init(task) < 0)
		return -1;

	if (os_task_init(task) < 0)
		return -1;

	breakpoint_hw_destroy(task);

	return 0;
}

static int leader_cleanup(struct task *leader)
{
	if (!leader)
		return 0;

	if (--leader->threads)
		return 0;
	
	library_clear_all(leader);
	breakpoint_clear_all(leader);
	backtrace_destroy(leader);

	list_del(&leader->leader_list);

	return 1;
}

static void leader_release(struct task *leader)
{
	if (!leader_cleanup(leader))
		return;

	free(leader);
}

static void task_destroy(struct task *task)
{
	struct task *leader = task->leader;

	if (task->deleted)
		return;

	task->deleted = 1;

	arch_task_destroy(task);
	os_task_destroy(task);
	detach_task(task);
	rb_erase(&task->pid_node, &pid_tree);

	if (leader != task) {
		list_del(&task->task_list);
		free(task);
	}

	leader_release(leader);
}

struct task *task_new(pid_t pid)
{
	struct task *task = malloc(sizeof(*task));

	if (!task)
		return NULL;

	memset(task, 0, sizeof(*task));

	task->pid = pid;
	task->traced = 0;
	task->stopped = 0;
	task->was_stopped = 0;

	INIT_LIST_HEAD(&task->task_list);
	INIT_LIST_HEAD(&task->leader_list);
#if HW_BREAKPOINTS > 1
	INIT_LIST_HEAD(&task->hw_bp_list);
#endif

	library_setup(task);

	if (task_init(task) < 0)
		goto fail1;

	init_event(task);

	insert_pid(task);

	return task;
fail1:
	task_destroy(task);
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

	each_task(leader, &remove_task_cb, leader);
	breakpoint_disable_all(leader);

	os_task_destroy(leader);
	arch_task_destroy(leader);
	leader_cleanup(leader);

	assert(leader->threads == 0);

	if (task_init(leader) < 0)
		goto fail;

	if (server_connected())
		task->attached = 0;

	assert(leader->leader == leader);
	assert(leader->threads_stopped == 1);

	if (leader_setup(leader) < 0)
		goto fail;

	return 0;
fail:
	task_destroy(leader);
	return -1;
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

	task = task_new(pid);
	if (!task)
		goto fail2;

	if (trace_wait(task))
		goto fail1;

	if (trace_set_options(task) < 0)
		goto fail2;

	if (server_connected())
		task->attached = 0;

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

	newtask->is_64bit = task->is_64bit;
	newtask->attached = task->attached;

	breakpoint_hw_clone(newtask);

	return 0;
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

	if (task->skip_bp)
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
	breakpoint_put(task->skip_bp);

	task->breakpoint = NULL;
	task->skip_bp = NULL;
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

	return task;
fail2:
	task_destroy(task);
fail1:
	return NULL;
}

static void show_attached(struct task *task, void *data)
{
	fprintf(stderr, "+++ process pid=%d attached (%s) +++\n", task->pid, library_execname(task->leader));
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

		assert(task->leader == leader);

		task->is_64bit = leader->is_64bit;
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

void remove_proc(struct task *leader)
{
	debug(DEBUG_FUNCTION, "pid=%d", leader->pid);

	assert(leader->leader == leader);

	breakpoint_disable_all(leader);
	each_task(leader, &remove_task_cb, NULL);
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

