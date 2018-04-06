/*
 * This file is part of mtrace-ng.
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

#ifndef _INC_BACKEND_H
#define _INC_BACKEND_H

#include "config.h"

#include "arch.h"
#include "os.h"
#include "forward.h"
#include "mtrace.h"

#include <stddef.h>
#include <sys/types.h>

/* Convert a pid to a path to the corresponding binary.  */
char *pid2name(pid_t pid);

/* return the cwd of a pid.  */
char *pid2cwd(pid_t pid);

/* Given a pid, find a leader of thread group.  */
pid_t process_leader(pid_t pid);

/* Given a pid of leader thread, fill in pids of all the tasks.  The
 * function will initialize the pointer *ret_tasks to a
 * newly-allocated array, and will store number of elements in that
 * array to *ret_n.  You have to free that buffer when you don't need
 * it anymore.  */
int process_tasks(pid_t pid, pid_t **ret_tasks, size_t *ret_n);

/* set tracing options, the task must be in state traced */
int trace_set_options(struct task *task);

/* make the forked process traceable */
void trace_me(void);

/* stop tracing of a task. */
int untrace_task(struct task *task);

/* Called when mtrace-ng needs to attach to task */
int trace_attach(struct task *task);

/* wait for a task ready for tracing */
int trace_wait(struct task *task);

/* continue process */
int continue_task(struct task *task, int signum);

/* Return current instruction pointer  */
arch_addr_t get_instruction_pointer(struct task *task);

/* Set instruction pointer of task to addr */
void set_instruction_pointer(struct task *task, arch_addr_t addr);

/* do a single step */
int do_singlestep(struct task *task, struct  breakpoint *bp);

/* handle a single step event */
int handle_singlestep(struct task *task, int (*singlestep)(struct task *task), struct breakpoint *bp);

/* Find and return caller address, i.e. the address where the current
 * function returns.  */
arch_addr_t get_return_addr(struct task *task);

/* get address of IP register */
unsigned int ip_reg_addr(void);

#if HW_BREAKPOINTS > 0
/* returns true if the hw breakpoint is pendig */
int get_hw_bp_state(struct task *task, unsigned int n);

/* set instruction hw breakpoint */
int set_hw_bp(struct task *task, unsigned int n, arch_addr_t addr);

/* remove instruction hw breakpoint */
int reset_hw_bp(struct task *task, unsigned int n);

/* remove all instruction hw breakpoints */
int reset_all_hw_bp(struct task *task);
#endif

/* save the process context (state, registers, stack pointer) */
int fetch_context(struct task *task);

/* save the process context for parameter fetching */
void save_param_context(struct task *task);

/* get return value of a remote function */
unsigned long fetch_retval(struct task *task);

/* get parameter value of a remote function */
unsigned long fetch_param(struct task *task, unsigned int param);

/* get register value of a remote function */
unsigned long fetch_reg(struct task *task, unsigned int reg);

/* Should copy len bytes from address addr of task to local buffer dst  */
ssize_t copy_from_proc(struct task *task, arch_addr_t addr, void *dst, size_t len);

/* Should copy len bytes from local buffer src to address addr of the remote task */
ssize_t copy_to_proc(struct task *task, arch_addr_t addr, const void *src, size_t len);

/* Should copy len bytes from address addr of remote task to local
 * buffer dst and overwrite the task data with src */
ssize_t copy_from_to_proc(struct task *task, arch_addr_t addr, const void *src, void *dst, size_t len);

/* Should copy max. len of a string from address addr from the remote task
 * to local buffer dst */
ssize_t copy_str_from_proc(struct task *task, arch_addr_t addr, char *dst, size_t len);

/* Called at some point after we have attached to the process.  This callback
 * should insert an introspection breakpoint for handling dynamic linker
 * library loads. */
int linkmap_init(struct task *task, arch_addr_t dyn_addr);

/* This should extract entry point address and interpreter (dynamic
 * linker) bias if possible.  Returns 0 if there were no errors, -1
 * otherwise.  Sets *entryp and *interp_biasp to non-zero values if
 * the corresponding value is known, or zero otherwise; this is not
 * done for pointers that are NULL.  */
int process_get_entry(struct task *task, unsigned long *entryp, unsigned long *interp_biasp);

/* The following callbacks have to be implemented in OS backend if
 * os.h defines OS_HAVE_PROCESS_DATA. */
#ifdef OS_HAVE_PROCESS_DATA
int os_task_init(struct task *task);
void os_task_destroy(struct task *task);
int os_task_clone(struct task *retp, struct task *task);
#endif

/* The following callbacks have to be implemented in OS backend if
 * os.h defines ARCH_HAVE_PROCESS_DATA. */
#ifdef ARCH_HAVE_PROCESS_DATA
int arch_task_init(struct task *task);
void arch_task_destroy(struct task *task);
int arch_task_clone(struct task *retp, struct task *task);
#endif

/* stop all thread of a given task */
void stop_threads(struct task *task);

/* scan writeable memory segments */
void *mem_scan(struct task *task, struct mt_msg *cmd, void *payload, unsigned long *data_len);

/* os specific init */
int os_init(void);

/* wait for the next unqueued trace event */
struct task *wait_event();

/* wakeup a wait_event() call */
void wait_event_wakeup(void);

/* return true the elf file is 64 bit */
int is_64bit(struct mt_elf *mte);

/* change user id of a running process */
void change_uid(void);

#endif

