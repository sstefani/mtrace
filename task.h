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

#ifndef _INC_TASK_H
#define _INC_TASK_H

#include "config.h"

#include <time.h>
#include <sys/time.h>

#include "forward.h"
#include "mtrace.h"
#include "dict.h"
#include "event.h"
#include "sysdep.h"
#include "arch.h"
#include "list.h"
#include "rbtree.h"
#include "report.h"

struct task {
	/* current pendig event */
	struct event event;

	unsigned int is_64bit:1;
	unsigned int attached:1;
	unsigned int deleted:1;
	unsigned int about_exit:1;
	unsigned int stopped:1;
	unsigned int is_new:1;
	unsigned int bad:1;
	unsigned int bp_skipped:1;

	struct breakpoint *breakpoint;
	struct library_symbol *libsym;
	struct context context;		/* process context (registers, stack) */
	struct context saved_context;	/* context for fetch_param() */

	/* arch specific task data */
#ifdef TASK_HAVE_PROCESS_DATA
	struct arch_task_data arch;
#endif

	/* pointer to a breakpoint which was interrupt by a signal during skip */
	struct breakpoint *skip_bp;

#if HW_BREAKPOINTS > 0
	/* array of active hw breakpoints */
	struct breakpoint *hw_bp[HW_BREAKPOINTS];
#endif

	/* process id */
	pid_t pid;

	/* points to the leader thread */
	struct task *leader;

	/* set in leader: number of stopped threads including the leader */
	unsigned int threads_stopped;

	/* set in leader: dictionary of breakpoints */
	struct dict *breakpoints;

	/* set in leader: backtrace pimpl */
	void *backtrace;

	/* linked list of libraries, the first entry is the executable itself */
	struct list_head libraries_list;

	/* red black tree of libraries */
	struct rb_root libraries_tree;

	/* Thread chaining to leader */
	struct list_head task_list;

	/* set in leader: number of threads including the leader */
	unsigned int threads;

	/* struct task chaining. */
	struct list_head leader_list;

	/* halt time for debugging purpose */
	struct timespec halt_time;

	/* defered event function */
	int (*defer_func)(struct task *task, void *data);

	/* defered event data */
	void *defer_data;

#if HW_BREAKPOINTS > 1
	/* set in leader: list of hw breakpoints */
	struct list_head hw_bp_list;

	/* set in leader: number of registered hw breakpoints */
	unsigned long hw_bp_num;
#endif

	/* os specific task data */
#ifdef OS_HAVE_PROCESS_DATA
	struct os_task_data os;
#endif
};

int process_exec(struct task *task);

struct task *task_new(pid_t pid);

struct task *task_create(char **argv);

void open_pid(pid_t pid);

/* Clone the contents of a task */
int task_clone(struct task *task, struct task *newtask);

/* Fork the contents of a task */
int task_fork(struct task *task, struct task *newtask);

/* reset all breakpoints for task */
void task_reset_bp(struct task *task);

/* Iterate through the leader tasks that mtrace-ng currently traces. */
void each_process(void (*cb)(struct task *task));

/* Iterate through list of tasks of a given leader task asks */
void each_task(struct task *leader, void (*cb)(struct task *task, void *data), void *data);

/* Iterate through all allocated pids */
void each_pid(void (*cb)(struct task *task));

/* Remove task from the list of traced processes, drop any events in the event queue, destroy it and free memory. */
void remove_task(struct task *task);

/* invalidate all breakpoints and call remove_proc */
void untrace_proc(struct task *leader);

/* Remove all threads of the process from the list of traced processes, drop any events in the event queue, destroy it and free memory. */
void remove_proc(struct task *leader);

/* halt a task */
void stop_task(struct task *task);

/* return true if no more task is traced */
int task_list_empty(void);

/* return true if task is 64 bit */
static inline int task_is_64bit(struct task *task)
{
	return task->is_64bit;
}

struct pid_hash {
	unsigned int	num;
	unsigned int	size;
	struct task *	tasks[0];
};

#define PID_HASH(pid)	((pid) % ARRAY_SIZE(pid_hash))
#define PID_HASH_SIZE	256

extern struct pid_hash *pid_hash[PID_HASH_SIZE];
extern struct task *pid2task(pid_t pid);
#endif

