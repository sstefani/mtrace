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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>

#include "backend.h"
#include "task.h"
#include "arch.h"

#if (!defined(PTRACE_PEEKUSER) && defined(PTRACE_PEEKUSR))
#define PTRACE_PEEKUSER PTRACE_PEEKUSR
#endif

#if (!defined(PTRACE_POKEUSER) && defined(PTRACE_POKEUSR))
#define PTRACE_POKEUSER PTRACE_POKEUSR
#endif

arch_addr_t get_instruction_pointer(struct task *task)
{
	return ARCH_ADDR_T(task->context.regs.ARM_pc);
}

void set_instruction_pointer(struct task *task, arch_addr_t addr)
{
	unsigned long val = (unsigned long)addr;

	if (task->context.regs.ARM_pc == (long)val)
		return;

	task->context.regs.ARM_pc = val;

	if (ptrace(PTRACE_POKEUSER, task->pid, offsetof(struct pt_regs, ARM_pc), val) == -1) {
		if (errno != ESRCH)
			fprintf(stderr, "pid=%d Couldn't set instruction pointer: %s\n", task->pid, strerror(errno));
	}
}

arch_addr_t get_return_addr(struct task *task)
{
	return ARCH_ADDR_T(task->context.regs.ARM_lr);
}

int fetch_context(struct task *task)
{
	if (ptrace(PTRACE_GETREGS, task->pid, 0, &task->context.regs) == -1) {
		if (errno != ESRCH)
			fprintf(stderr, "pid=%d Couldn't fetch register context: %s\n", task->pid, strerror(errno));

		memset(&task->context.regs, 0, sizeof(task->context.regs));
		return -1;
	}
	return 0;
}

void save_param_context(struct task *task)
{
	task->saved_context = task->context;
}

unsigned long fetch_param(struct task *task, unsigned int param)
{
	unsigned long val;

	switch (param) {
	case 0:
		val = task->saved_context.regs.ARM_r0;
		break;
	case 1:
		val = task->saved_context.regs.ARM_r1;
		break;
	case 2:
		val = task->saved_context.regs.ARM_r2;
		break;
	case 3:
		val = task->saved_context.regs.ARM_r3;
		break;
	default:
		copy_from_proc(task, task->saved_context.regs.ARM_sp + (param - 4) * sizeof(val), &val, sizeof(val));
	}
	return val;
}

unsigned long fetch_retval(struct task *task)
{
	return task->context.regs.ARM_r0;
}

unsigned long fetch_reg(struct task *task, unsigned int reg)
{
	unsigned long val;

	switch(reg) {
	case offsetof(struct pt_regs, ARM_cpsr):
		val = task->context.regs.ARM_cpsr;
		break;
	case offsetof(struct pt_regs, ARM_pc):
		val = task->context.regs.ARM_pc;
		break;
	case offsetof(struct pt_regs, ARM_lr):
		val = task->context.regs.ARM_lr;
		break;
	case offsetof(struct pt_regs, ARM_sp):
		val = task->context.regs.ARM_sp;
		break;
	case offsetof(struct pt_regs, ARM_ip):
		val = task->context.regs.ARM_ip;
		break;
	case offsetof(struct pt_regs, ARM_fp):
		val = task->context.regs.ARM_fp;
		break;
	case offsetof(struct pt_regs, ARM_r10):
		val = task->context.regs.ARM_r10;
		break;
	case offsetof(struct pt_regs, ARM_r9):
		val = task->context.regs.ARM_r9;
		break;
	case offsetof(struct pt_regs, ARM_r8):
		val = task->context.regs.ARM_r8;
		break;
	case offsetof(struct pt_regs, ARM_r7):
		val = task->context.regs.ARM_r7;
		break;
	case offsetof(struct pt_regs, ARM_r6):
		val = task->context.regs.ARM_r6;
		break;
	case offsetof(struct pt_regs, ARM_r5):
		val = task->context.regs.ARM_r5;
		break;
	case offsetof(struct pt_regs, ARM_r4):
		val = task->context.regs.ARM_r4;
		break;
	case offsetof(struct pt_regs, ARM_r3):
		val = task->context.regs.ARM_r3;
		break;
	case offsetof(struct pt_regs, ARM_r2):
		val = task->context.regs.ARM_r2;
		break;
	case offsetof(struct pt_regs, ARM_r1):
		val = task->context.regs.ARM_r1;
		break;
	case offsetof(struct pt_regs, ARM_r0):
		val = task->context.regs.ARM_r0;
		break;
	case offsetof(struct pt_regs, ARM_ORIG_r0):
		val = task->context.regs.ARM_ORIG_r0;
		break;
	default:
		abort();
	}
	return val;
}

