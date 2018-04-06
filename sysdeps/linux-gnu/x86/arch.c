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

#include <assert.h>
#include <backend.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

#include "arch.h"
#include "mtelf.h"
#include "task.h"

/* Breakpoint access modes */
#define	BP_X	1
#define BP_RW	2
#define BP_W	4

int get_hw_bp_state(struct task *task, unsigned int n)
{
	long ret;

	errno = 0;
	ret = ptrace(PTRACE_PEEKUSER, task->pid, offsetof(struct user, u_debugreg[6]), 0);
	if (unlikely(ret == -1 && errno)) {
		if (errno != ESRCH)
			fprintf(stderr, "PTRACE_PEEKUSER u_debugreg[6] pid=%d %s\n", task->pid, strerror(errno));

		return 0;
	}
	return (ret & (1 << n)) != 0;
}

static int _apply_hw_bp(struct task *task, uint32_t dr7)
{
	long ret;

	task->arch.dr7 = dr7;

	ret = ptrace(PTRACE_POKEUSER, task->pid, offsetof(struct user, u_debugreg[7]), task->arch.dr7);
	if (unlikely(ret)) {
		if (errno != ESRCH) {
			fprintf(stderr, "PTRACE_POKEUSER u_debugreg[7] pid=%d %s\n", task->pid, strerror(errno));
			return -1;
		}
	}
	return 0;
}

static inline int apply_hw_bp(struct task *task, uint32_t dr7)
{
	if (dr7 == task->arch.dr7)
		return 0;

	return _apply_hw_bp(task, dr7);
}

static int set_breakpoint_addr(struct task *task, arch_addr_t addr, unsigned int n)
{
	long ret;

#ifdef __x86_64__
	if (!task_is_64bit(task))
		addr &= 0xffffffff;
#endif

	if (task->arch.hw_bp[n] == addr)
		return 0;

	ret = ptrace(PTRACE_POKEUSER, task->pid, offsetof(struct user, u_debugreg[n]), addr);
	if (unlikely(ret)) {
		if (errno != ESRCH) {
			fprintf(stderr, "PTRACE_POKEUSER u_debugreg[%d] pid=%d %s\n", n, task->pid, strerror(errno));
			return -1;
		}
	}

	task->arch.hw_bp[n] = addr;

	return 0;
}

static int set_breakpoint_mode(struct task *task, unsigned int n, int type, int len, int local, int global)
{
	uint32_t mode;
	uint32_t dr7, mask;

	mask = (0b1111U << (16 + 4 * n)) | (0b11U << (2 * n));

	switch(type) {
	case BP_X:
		mode = 0b0000U;
		break;
	case BP_W:
		mode = 0b0001U;
		break;
	case BP_RW:
		mode = 0b0011U;
		break;
	default:
		fprintf(stderr, "invalid hw breakpoint type\n");
		return -1;
	}

	switch(len) {
	case 1:
		mode |= 0b0000U;
		break;
	case 2:
		mode |= 0b0100U;
		break;
	case 4:
		mode |= 0b1100U;
		break;
	case 8:
		mode |= 0b1000U;
		break;
	}

	dr7 = task->arch.dr7 & ~mask;

	dr7 |= mode << (16 + 4 * n);

	if (local) {
		dr7 |= 0b01U << (2 * n);
		dr7 |= 1 << 8;
	}
	else
	if (!(dr7 & 0b01010101U))
		dr7 &= ~(1 << 8);

	if (global) {
		dr7 |= 0b10U << (2 * n);
		dr7 |= 1 << 9;
	}
	else
	if (!(dr7 & 0b10101010U))
		dr7 &= ~(1 << 9);

	return apply_hw_bp(task, dr7);
}

int set_hw_bp(struct task *task, unsigned int n, arch_addr_t addr)
{
#if 0
	if (reset_hw_bp(task, n) == -1)
		return -1;
#endif
	if (unlikely(set_breakpoint_addr(task, addr, n) == -1))
		return -1;

	return set_breakpoint_mode(task,
		n,	/* n */
		BP_X,	/* type */
		1,	/* len */
		1,	/* local */
		0	/* global */
	);
}

int reset_hw_bp(struct task *task, unsigned int n)
{
	uint32_t dr7, mask;

	mask = (0b1111U << (16 + 4 * n)) | (0b11U << (2 * n));

	dr7 = task->arch.dr7 & ~mask;

	if (!(dr7 & 0b01010101U))
		dr7 &= ~(1 << 8);

	if (!(dr7 & 0b10101010U))
		dr7 &= ~(1 << 9);

	return apply_hw_bp(task, dr7);
}

int reset_all_hw_bp(struct task *task)
{
	return apply_hw_bp(task, 0);
}

int is_64bit(struct mt_elf *mte)
{
	return mte->ehdr.e_machine != EM_386;
}

int arch_task_init(struct task *task)
{
	unsigned int i;

	for(i = 0; i != HW_BREAKPOINTS; ++i)
		task->arch.hw_bp[i] = 0;

	return _apply_hw_bp(task, 0);
}

void arch_task_destroy(struct task *task)
{
	apply_hw_bp(task, 0);
}

int arch_task_clone(struct task *retp, struct task *task)
{
	(void)retp;
	(void)task;

	return 0;
}

