/*
 * This file is part of mtrace.
 * Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

#include "arch.h"
#include "mtelf.h"
#include "task.h"

/* Breakpoint access modes */
enum {
	BP_X = 1,
	BP_RW = 2,
	BP_W = 4,
};

static int set_breakpoint_addr(struct task *task, arch_addr_t addr, int n)
{
	int ret;

	ret = ptrace(PTRACE_POKEUSER, task->pid, offsetof(struct user, u_debugreg[n]), addr);
	if (ret) {
		if (errno != ESRCH) {
			fprintf(stderr, "PTRACE_POKEUSER u_debugreg[%d] pid=%d %s\n", n, task->pid, strerror(errno));
			return -1;
		}
	}
	return 0;
}

static int toggle_breakpoint(struct task *task, int n, int type, int len, int local, int global, int set)
{
	long ret;
	int xtype, xlen;
	unsigned long dr7, vdr7;

	switch (type) {
	case BP_X:
		xtype = 0;
		break;
	case BP_W:
		xtype = 1;
		break;
	case BP_RW:
		xtype = 3;
		break;
	}

	switch (len) {
	case 1:
		xlen = 0;
		break;
	case 2:
		xlen = 4;
		break;
	case 4:
		xlen = 0xc;
		break;
	case 8:
		xlen = 8;
		break;
	}

	vdr7 = (xlen | xtype) << 16;
	vdr7 <<= 4 * n;

	if (local) {
		vdr7 |= 1 << (2 * n);
		vdr7 |= 1 << 8;
	}
	if (global) {
		vdr7 |= 2 << (2 * n);
		vdr7 |= 1 << 9;
	}

	dr7 = task->arch.dr7;
	if (set)
		dr7 |= vdr7;
	else
		dr7 &= ~vdr7;

	if (dr7 != task->arch.dr7) {
		task->arch.dr7 = dr7;

		ret = ptrace(PTRACE_POKEUSER, task->pid, offsetof(struct user, u_debugreg[7]), task->arch.dr7);
		if (ret) {
			if (errno != ESRCH) {
				fprintf(stderr, "PTRACE_POKEUSER u_debugreg[7] pid=%d %s\n", task->pid, strerror(errno));
				return -1;
			}
		}
	}
	return 0;
}

int set_hw_bp(struct task *task, unsigned int slot, arch_addr_t addr)
{
	if (set_breakpoint_addr(task, addr, slot) == -1)
		return -1;

	return toggle_breakpoint(task,
		slot,	/* n */
		BP_X,	/* type */
		1,	/* len */
		1,	/* local */
		0,	/* global */
		1	/* set */
	);
}

int reset_hw_bp(struct task *task, unsigned int slot, arch_addr_t addr)
{
	return toggle_breakpoint(task,
		slot,	/* n */
		BP_X,	/* type */
		1,	/* len */
		1,	/* local */
		0,	/* global */
		0	/* set */
	);
}

int is_64bit(struct mt_elf *mte)
{
	return mte->ehdr.e_machine != EM_386;
}

int arch_task_init(struct task *task)
{
	long ret;

	ret = ptrace(PTRACE_PEEKUSER, task->pid, offsetof(struct user, u_debugreg[7]), 0);
	if (ret == -1 && errno) {
		if (errno != ESRCH) {
			fatal("PTRACE_PEEKUSER u_debugreg[7] pid=%d %s\n", task->pid, strerror(errno));
			return -1;
		}
		return 0;
	}

	task->arch.dr7 = ret;

	return 0;
}

void arch_task_destroy(struct task *task)
{
}

int arch_task_clone(struct task *retp, struct task *task)
{
	return 0;
}

