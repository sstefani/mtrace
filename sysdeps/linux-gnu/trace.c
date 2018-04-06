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

#include "config.h"

#define _GNU_SOURCE

#include <asm/unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/uio.h>

#include "backend.h"
#include "breakpoint.h"
#include "debug.h"
#include "event.h"
#include "library.h"
#include "main.h"
#include "options.h"
#include "task.h"
#include "timer.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile pid_t wakeup_pid = -1;

static inline int task_kill(struct task *task, int sig)
{
	errno = 0;

	return syscall(__NR_tgkill, task->leader->pid, task->pid, sig);
}

static inline int wait_task(struct task *task, int *status)
{
	int ret;

	ret = TEMP_FAILURE_RETRY(waitpid(task ? task->pid : -1, status, __WALL));
	if (ret == -1) {
		if (task)
			fprintf(stderr, "!!!%s: waitpid pid=%d %s\n", __func__,  task->pid, strerror(errno));
	}
	return ret;
}

static int trace_setup(struct task *task, int status, int signum)
{
	int sig;

	task->attached = 1;
	task->stopped = 1;
	task->leader->threads_stopped++;
	task->event.type = EVENT_NEW;
	task->event.e_un.signum = 0;

	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "!!!pid=%d not stopped\n", task->pid);
		return -1;
	}

	sig = WSTOPSIG(status);

	if (sig != signum) {
		task->event.e_un.signum = sig;

		fprintf(stderr, "!!!pid=%d unexpected trace signal (got:%d expected:%d)\n", task->pid, sig, signum);
		return -1;
	}

	return 0;
}

static int _trace_wait(struct task *task, int signum)
{
	int status;

	if (unlikely(wait_task(task, &status) == -1))
		return -1;

	if (WIFEXITED(status))
		return -1;

	return trace_setup(task, status, signum);
}

int trace_wait(struct task *task)
{
	assert(task->attached == 0);

	if (_trace_wait(task, SIGTRAP))
		return -1;

	return 0;
}

static int child_event(struct task *task, enum event_type ev)
{
	unsigned long data;

	debug(DEBUG_EVENT, "child event %d pid=%d, newpid=%d", ev, task->pid, task->event.e_un.newpid);

	if (unlikely(ptrace(PTRACE_GETEVENTMSG, task->pid, NULL, &data) == -1)) {
		debug(DEBUG_EVENT, "PTRACE_GETEVENTMSG pid=%d %s", task->pid, strerror(errno));
		return -1;
	}

	int pid = data;

	if (!pid2task(pid)) {
		struct task *child = task_new(pid);

		if (unlikely(!child))
			return -1;

		child->attached = 1;
	}

	task->event.e_un.newpid = pid;
	task->event.type = ev;

	return 0;
}

static int _process_event(struct task *task, int status)
{
	int sig = WSTOPSIG(status);

	task->stopped = 1;

	assert(task->event.type == EVENT_NONE);

	if (WIFSIGNALED(status)) {
		debug(DEBUG_EVENT, "EXIT_SIGNAL: pid=%d, signum=%d", task->pid, task->event.e_un.signum);

		task->event.type = EVENT_EXIT_SIGNAL;
		task->event.e_un.signum = WTERMSIG(status);
		return 0;
	}

	if (WIFEXITED(status)) {
		debug(DEBUG_EVENT, "EXIT: pid=%d, status=%d", task->pid, task->event.e_un.ret_val);

		task->event.type = EVENT_EXIT;
		task->event.e_un.ret_val = WEXITSTATUS(status);
		return 0;
	}

	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "!!!not WIFSTOPPED pid=%d\n", task->pid);
		return -1;
	}

	if (unlikely(task->is_new)) {
		if (sig == SIGSTOP && !(status >> 16)) {
			task->event.type = EVENT_NEW;
			task->event.e_un.signum  = 0;

			return 0;
		}

		if (!task->bad) {
			fprintf(stderr, "!!!unexpected state for pid=%d, expected signal SIGSTOP (%d %d)\n", task->pid, sig, status >> 16);
			task->bad = 1;
		}
	}

	switch(status >> 16)  {
	case 0:
		break;
	case PTRACE_EVENT_VFORK:
		debug(DEBUG_EVENT, "VFORK: pid=%d, newpid=%d", task->pid, task->event.e_un.newpid);
		return child_event(task, EVENT_VFORK);
	case PTRACE_EVENT_FORK:
		debug(DEBUG_EVENT, "FORK: pid=%d, newpid=%d", task->pid, task->event.e_un.newpid);
		return child_event(task, EVENT_FORK);
	case PTRACE_EVENT_CLONE:
		debug(DEBUG_EVENT, "CLONE: pid=%d, newpid=%d", task->pid, task->event.e_un.newpid);
		return child_event(task, EVENT_CLONE);
	case PTRACE_EVENT_EXEC:
		task->event.type = EVENT_EXEC;
		debug(DEBUG_EVENT, "EXEC: pid=%d", task->pid);
		return 0;
	case PTRACE_EVENT_EXIT:
	 {
		unsigned long data;

		debug(DEBUG_EVENT, "ABOUT_EXIT: pid=%d", task->pid);

		if (unlikely(ptrace(PTRACE_GETEVENTMSG, task->pid, NULL, &data) == -1)) {
			debug(DEBUG_EVENT, "PTRACE_GETEVENTMSG pid=%d %s", task->pid, strerror(errno));
			return -1;
		}
		task->event.e_un.ret_val = WEXITSTATUS(data);
		task->event.type = EVENT_ABOUT_EXIT;
		return 0;
	 }
	default:
	 	fprintf(stderr, "!!!PTRACE_EVENT_????? pid=%d %d\n", task->pid, status >> 16);
		break;
	}

	if (!sig)
		fprintf(stderr, "!!!%s: sig == 0 pid=%d\n", __func__, task->pid);

	if (sig == SIGSTOP) {
		siginfo_t siginfo;

		if (unlikely(ptrace(PTRACE_GETSIGINFO, task->pid, 0, &siginfo) == -1))
			sig = 0;
		else {
			if (likely(siginfo.si_pid == mtrace_pid))
				sig = 0;
			else
				fprintf(stderr, "!!!%s: SIGSTOP pid=%d %d %d %d %d\n", __func__, task->pid, siginfo.si_signo, siginfo.si_errno, siginfo.si_code, siginfo.si_pid);
		}
	}

	task->event.type = EVENT_SIGNAL;
	task->event.e_un.signum = sig;

	debug(DEBUG_EVENT, "SIGNAL: pid=%d, signum=%d", task->pid, sig);
	return sig;
}

static struct task * process_event(struct task *task, int status)
{
	struct task *leader = task->leader;
	struct breakpoint *bp = NULL;
	arch_addr_t ip;
	int sig;

	assert(task->stopped == 0);
	assert(leader != NULL);

	if (unlikely(options.verbose > 1))
		start_time(&task->halt_time);

	leader->threads_stopped++;

	sig = _process_event(task, status);
	if (sig < 0) {
		continue_task(task, 0);
		return NULL;
	}

	if (task->event.type == EVENT_NONE) {
		continue_task(task, task->event.e_un.signum);
		return NULL;
	}

	if (unlikely(sig != SIGTRAP))
		return task;

	if (unlikely(fetch_context(task) == -1)) {
		task->event.type = EVENT_NONE;
		continue_task(task, 0);
		return NULL;
	}

	ip = get_instruction_pointer(task);

#if HW_BREAKPOINTS > 0
	unsigned int i;

	for(i = 0; i < HW_BREAKPOINTS; ++i) {
		if (task->hw_bp[i] && task->hw_bp[i]->addr == ip) {
			if (likely(get_hw_bp_state(task, i)))
				bp = task->hw_bp[i];
			break;
		}
	}

	if (bp) {
		assert(bp->type != BP_SW);
		assert(bp->hw_bp_slot == i);
	}
	else
#endif
	{
		bp = breakpoint_find(leader, ip - DECR_PC_AFTER_BREAK);
		if (unlikely(!bp)) {
			fprintf(stderr, "!!!%s: SIGTRAP pid=%d\n", __func__, task->pid);
			return task;
		}
#if HW_BREAKPOINTS > 0
		assert(bp->type != BP_HW_SCRATCH);
		assert(bp->hw == 0);
#endif

		set_instruction_pointer(task, bp->addr);
	}
#if 1
	assert(bp->enabled);
#else
	if (!bp->enabled)
		return;
#endif
	task->event.type = EVENT_BREAKPOINT;
	task->event.e_un.breakpoint = breakpoint_get(bp);

	debug(DEBUG_EVENT, "BREAKPOINT: pid=%d, addr=%#lx", task->pid, task->event.e_un.breakpoint->addr);

	return task;
}

void trace_me(void)
{
	debug(DEBUG_PROCESS, "pid=%d", getpid());

	prctl(PR_SET_PDEATHSIG, SIGKILL);

	if (unlikely(ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)) {
		fprintf(stderr, "PTRACE_TRACEME pid=%d %s\n", getpid(), strerror(errno));
		exit(1);
	}
}

static inline int chk_signal(struct task *task, int signum)
{
#if 1
	if (signum == SIGSTOP)
		fprintf(stderr, "!!!%s: SIGSTOP pid=%d\n", __func__, task->pid);

	if (signum == SIGTRAP)
		fprintf(stderr, "!!!%s: SIGTRAP pid=%d\n", __func__, task->pid);
#endif

	return signum;
}

int untrace_task(struct task *task)
{
	int ret;
	int sig = 0;

	assert(task->stopped);

	if (unlikely(ptrace(PTRACE_SETOPTIONS, task->pid, 0, (void *)0) == -1)) {
		if (errno != ESRCH)
			fprintf(stderr, "PTRACE_SETOPTIONS pid=%d %s\n", task->pid, strerror(errno));
		ret = -1;
		goto skip;
	}

	if (task->event.type == EVENT_SIGNAL || task->event.type == EVENT_NONE)
		sig = chk_signal(task, sig);

	if (unlikely(ptrace(PTRACE_DETACH, task->pid, 0, sig) == -1)) {
		if (errno != ESRCH)
			fprintf(stderr, "PTRACE_DETACH pid=%d %s\n", task->pid, strerror(errno));
		ret = -1;
	}

	task_kill(task, SIGCONT);
skip:
	task->leader->threads_stopped--;
	task->stopped = 0;
	task->attached = 0;

	return ret;
}

void stop_task(struct task *task)
{
	assert(task->attached);
	assert(task->leader != NULL);

	if (!task->stopped) {
		int status;

		task_kill(task, SIGSTOP);
		if (wait_task(task, &status) != -1)
			_process_event(task, status);
	}
}

int trace_attach(struct task *task)
{
	debug(DEBUG_PROCESS, "pid=%d", task->pid);

	assert(task->attached == 0);

	if (unlikely(ptrace(PTRACE_ATTACH, task->pid, 0, 0) == -1)) {
		if (errno != ESRCH)
			fprintf(stderr, "PTRACE_ATTACH pid=%d %s\n", task->pid, strerror(errno));
		return -1;
	}

	if (_trace_wait(task, SIGSTOP))
		return -1;

	return 0;
}

int trace_set_options(struct task *task)
{
	long options = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;

	debug(DEBUG_PROCESS, "pid=%d", task->pid);

	if (unlikely(ptrace(PTRACE_SETOPTIONS, task->pid, 0, (void *)options) == -1)) {
		if (errno != ESRCH)
			fprintf(stderr, "PTRACE_SETOPTIONS pid=%d %s\n", task->pid, strerror(errno));
		return -1;
	}
	return 0;
}

int continue_task(struct task *task, int signum)
{
	debug(DEBUG_PROCESS, "continue task pid=%d", task->pid);

	assert(task->leader != NULL);
	assert(task->stopped);

	if (signum >= 0x80)
		fprintf(stderr, "!!!signum >= 0x80 pid=%d: %d\n", task->pid, signum);

	task->leader->threads_stopped--;
	task->stopped = 0;
	task->event.type = EVENT_NONE;

	if (signum == SIGTRAP)
		fprintf(stderr, "!!!%s: SIGTRAP pid=%d\n", __func__, task->pid);

	if (unlikely(ptrace(PTRACE_CONT, task->pid, 0, chk_signal(task, signum)) == -1)) {
		if (errno != ESRCH)
			fprintf(stderr, "PTRACE_CONT pid=%d %s\n", task->pid, strerror(errno));
		return -1;
	}
	return 0;
}

static void do_stop_cb(struct task *task, void *data)
{
	(void)data;

	if (task->stopped)
		return;

	debug(DEBUG_EVENT, "task stop pid=%d", task->pid);

	task_kill(task, SIGSTOP);
}

void stop_threads(struct task *task)
{
	struct task *leader = task->leader;

	assert(task->leader != NULL);

	debug(DEBUG_EVENT, "stop threads pid=%d", task->pid);

	if (leader->threads != leader->threads_stopped) {
		struct timespec start;

		if (unlikely(options.verbose > 1))
			start_time(&start);

		each_task(leader, &do_stop_cb, NULL);

		while (leader->threads != leader->threads_stopped) {
			task = wait_event();

			if (task)
				queue_event(task);
		}

		if (unlikely(options.verbose > 1))
			set_timer(&start, &stop_time);
	}
}

int handle_singlestep(struct task *task, int (*singlestep)(struct task *task), struct breakpoint *bp)
{
	int status;
	int sig;

	assert(task->stopped);
	assert(task->skip_bp == NULL);
	assert(bp->enabled == 0);

	task->event.type = EVENT_NONE;

	if (unlikely(singlestep(task) == -1)) {
		fprintf(stderr, "!!!%s: single step failed pid=%d\n", __func__, task->pid);
		return -1;
	}

	if (unlikely(wait_task(task, &status) == -1))
		return 0;

	sig = _process_event(task, status);

	if (sig == -1) {
		fprintf(stderr, "!!!%s: failed _process_event pid=%d\n", __func__, task->pid);
		return 0;
	}

	assert(task->stopped);
	assert(task->event.type != EVENT_NONE);
	assert(task->event.type != EVENT_BREAKPOINT);

	if (task->event.type != EVENT_SIGNAL) {
		queue_event(task);
		return 1;
	}

	if (sig != SIGTRAP) {
		if (sig == SIGSTOP)
			fprintf(stderr, "!!!%s: SIGSTOP pid=%d\n", __func__, task->pid);
		queue_event(task);
		return 1;
	}

 	if (bp->break_insn) {
		queue_event(task);
		return 0;
	}

	task->event.type = EVENT_BREAKPOINT;
	task->event.e_un.breakpoint = bp;
	return 0;
}

#ifndef ARCH_SINGLESTEP
static int ptrace_singlestep(struct task *task)
{
	if (unlikely(ptrace(PTRACE_SINGLESTEP, task->pid, 0, 0) == -1)) {
		if (errno != ESRCH)
			fprintf(stderr, "!!!%s: PTRACE_SINGLESTEP pid=%d %s\n", __func__, task->pid, strerror(errno));
		return -1;
	}
	return 0;
}

int do_singlestep(struct task *task, struct breakpoint *bp)
{
	return handle_singlestep(task, ptrace_singlestep, bp);
}
#endif

struct task *wait_event(void)
{
	struct task *task;
	int status;
	int pid;

	pid = wait_task(NULL, &status);
	if (unlikely(pid == -1)) {
		if (errno == ECHILD)
			debug(DEBUG_EVENT, "No more traced programs");
		return NULL;
	}

	pthread_mutex_lock(&mutex);
	if (unlikely(pid == wakeup_pid)) {
		pid = 0;
		wakeup_pid = -1;
	}
	pthread_mutex_unlock(&mutex);

	if (!pid)
		return NULL;

	task = pid2task(pid);
	if (unlikely(!task)) {
		task = task_new(pid);

		if (likely(task))
			trace_setup(task, status, SIGSTOP);
		return NULL;
	}

	assert(!task->stopped);

	task = process_event(task, status);
	if (task)
		assert(task->stopped);
	return task;
}

void wait_event_wakeup(void)
{
	pid_t pid;

	pthread_mutex_lock(&mutex);
	if (wakeup_pid == -1) {
		pid = vfork();
		if (pid == 0)
			_exit(0);
		wakeup_pid = pid;
	}
	pthread_mutex_unlock(&mutex);
}

#ifndef HAVE_PROCESS_VM_READV
static ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags)
{
#ifdef __NR_process_vm_readv
	return syscall(__NR_process_vm_readv, pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
#else
	errno = ENOSYS;
	return -1;
#endif
}
#endif

ssize_t copy_from_proc(struct task *task, arch_addr_t addr, void *dst, size_t len)
{
	static int process_vm_call_nosys;
	ssize_t num_bytes;
	size_t n;
	union {
		long a;
		char c[sizeof(long)];
	} a;

	if (len > sizeof(a) && !process_vm_call_nosys) {
		struct iovec local[1];
		struct iovec remote[1];

		local[0].iov_base = dst;
		local[0].iov_len = len;
		remote[0].iov_base = (void *)addr;
		remote[0].iov_len = len;

		num_bytes = process_vm_readv(task->pid, local, 1, remote, 1, 0);
		if (unlikely(num_bytes != -1))
			return num_bytes;

		if (errno != EFAULT) {
			if (errno != ENOSYS) {
				fprintf(stderr, "!!!%s: pid=%d process_vm_readv: %s\n", __func__, task->pid, strerror(errno));
				return -1;
			}

			process_vm_call_nosys = 1;
		}
	}

	num_bytes = 0;
	n = sizeof(a.a);
	errno = 0;

	while (len) {
		a.a = ptrace(PTRACE_PEEKTEXT, task->pid, addr, 0);
		if (unlikely(a.a == -1 && errno)) {
			if (num_bytes && errno == EIO)
				break;
			return -1;
		}

		if (n > len)
			n = len;

		memcpy(dst, a.c, n);

		num_bytes += n;
		len -= n;

		dst += n;
		addr += n;
	}

	return num_bytes;
}

ssize_t copy_to_proc(struct task *task, arch_addr_t addr, const void *src, size_t len)
{
	ssize_t num_bytes;
	size_t n;
	union {
		long a;
		char c[sizeof(long)];
	} a;

	num_bytes = 0;
	n = sizeof(a.a);

	while (len) {
		if (n > len) {
			errno = 0;

			n = len;

			a.a = ptrace(PTRACE_PEEKTEXT, task->pid, addr, 0);
			if (unlikely(a.a == -1 && errno)) {
				if (num_bytes && errno == EIO)
					break;
				return -1;
			}
		}

		memcpy(a.c, src, n);

		a.a = ptrace(PTRACE_POKETEXT, task->pid, addr, a.a);
		if (unlikely(a.a == -1)) {
			if (num_bytes && errno == EIO)
				break;
			return -1;
		}

		num_bytes += n;
		len -= n;

		src += n;
		addr += n;
	}

	return num_bytes;
}

ssize_t copy_from_to_proc(struct task *task, arch_addr_t addr, const void *src, void *dst, size_t len)
{
	union {
		long a;
		char c[sizeof(long)];
	} a;

	ssize_t num_bytes = 0;
	size_t n = sizeof(a.a);

	errno = 0;

	while (len) {
		a.a = ptrace(PTRACE_PEEKTEXT, task->pid, addr, 0);
		if (unlikely(a.a == -1 && errno)) {
			if (num_bytes && errno == EIO)
				break;
			return -1;
		}

		if (n > len)
			n = len;

		memcpy(dst, a.c, n);
		memcpy(a.c, src, n);

		a.a = ptrace(PTRACE_POKETEXT, task->pid, addr, a.a);
		if (unlikely(a.a == -1)) {
			if (num_bytes && errno == EIO)
				break;
			return -1;
		}

		num_bytes += n;
		len -= n;

		src += n;
		dst += n;
		addr += n;
	}

	return num_bytes;
}

ssize_t copy_str_from_proc(struct task *task, arch_addr_t addr, char *dst, size_t len)
{
	union {
		long a;
		char c[sizeof(long)];
	} a;

	ssize_t num_bytes = 0;
	size_t n = sizeof(a.a);
	size_t i;

	errno = 0;

	if (!len--)
		return -1;

	while(len) {
		a.a = ptrace(PTRACE_PEEKTEXT, task->pid, addr, 0);
		if (unlikely(a.a == -1 && errno)) {
			if (num_bytes && errno == EIO)
				break;
			return -1;
		}

		if (n > len)
			n = len;

		for(i = 0; i < n; ++i) {
			if (!a.c[i])
				break;
		}

		memcpy(dst, a.c, i);

		num_bytes += i;
		len -= i;

		dst += i;
		addr += i;

		if (i < n)
			break;
	}

	*dst = 0;

	return num_bytes;
}

