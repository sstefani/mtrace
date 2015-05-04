/*
 * This file is part of mtrace.
 * Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
 *  This file is based on the ltrace source
 *
 * This work was sponsored by Rohde & Schwarz GmbH & Co. KG, Munich.
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

static inline unsigned long fix_machine(struct task *task, unsigned long val)
{
	if (!task_is_64bit(task))
		val &= 0xffffffff;

	return val;
}

arch_addr_t get_instruction_pointer(struct task *task)
{
#ifdef __powerpc64__
	return ARCH_ADDR_T(fix_machine(task, task->context.regs.nip));
#else
	return ARCH_ADDR_T(task->context.regs.nip);
#endif
}

void set_instruction_pointer(struct task *task, arch_addr_t addr)
{
	unsigned long val = (unsigned long)addr;

#ifdef __powerpc64__
	val = fix_machine(task, val);
#endif
	if (task->context.regs.nip == val)
		return;

	task->context.regs.nip = val;

	if (ptrace(PTRACE_POKEUSER, task->pid, sizeof(unsigned long) * PT_NIP, val) == -1) {
		if (errno != ESRCH)
			fprintf(stderr, "pid=%d Couldn't set instruction pointer: %s\n", task->pid, strerror(errno));
	}
}

arch_addr_t get_return_addr(struct task *task)
{
#ifdef __powerpc64__
	return ARCH_ADDR_T(fix_machine(task, task->context.regs.link));
#endif
	return ARCH_ADDR_T(task->context.regs.link);
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

#ifdef __powerpc64__
static unsigned long fetch_stack_64(struct task *task, unsigned int param)
{
	uint64_t val;

	copy_from_proc(task, (void *)task->saved_context.regs.gpr[PT_R1] + (param - 8 + 14) * sizeof(val), &val, sizeof(val));

	return val;
}
#endif

static unsigned long fetch_stack_32(struct task *task, unsigned int param)
{
	uint32_t val;

	copy_from_proc(task, task->saved_context.regs.gpr[PT_R1] + (param - 8 + 2) * sizeof(val), &val, sizeof(val));

	return val;
}

unsigned long fetch_param(struct task *task, unsigned int param)
{
	unsigned long val;

	switch (param) {
	case 0:
		val = task->saved_context.regs.gpr[PT_R3];
		break;
	case 1:
		val = task->saved_context.regs.gpr[PT_R4];
		break;
	case 2:
		val = task->saved_context.regs.gpr[PT_R5];
		break;
	case 3:
		val = task->saved_context.regs.gpr[PT_R6];
		break;
	case 4:
		val = task->saved_context.regs.gpr[PT_R7];
		break;
	case 5:
		val = task->saved_context.regs.gpr[PT_R8];
		break;
	case 6:
		val = task->saved_context.regs.gpr[PT_R9];
		break;
	case 7:
		val = task->saved_context.regs.gpr[PT_R10];
		break;
	default:
#ifdef __powerpc64__
		if (task_is_64bit(task)) {
			val = fetch_stack_64(task, param);
			break;
		}
#endif
		val = fetch_stack_32(task, param);
		break;
	}
#ifdef __powerpc64__
	val = fix_machine(task, val);
#endif
	return val;
}

unsigned long fetch_retval(struct task *task)
{
#ifdef __powerpc64__
	return fix_machine(task, task->context.regs.gpr[PT_R3]);
#else
	return task->context.regs.gpr[PT_R3];
#endif
}

unsigned long fetch_reg(struct task *task, unsigned int reg)
{
	unsigned long val;

	switch(reg) {
	case PT_R0:
		val = task->context.regs.gpr[PT_R0];
		break;
	case PT_R1:
		val = task->context.regs.gpr[PT_R1];
		break;
	case PT_R2:
		val = task->context.regs.gpr[PT_R2];
		break;
	case PT_R3:
		val = task->context.regs.gpr[PT_R3];
		break;
	case PT_R4:
		val = task->context.regs.gpr[PT_R4];
		break;
	case PT_R5:
		val = task->context.regs.gpr[PT_R5];
		break;
	case PT_R6:
		val = task->context.regs.gpr[PT_R6];
		break;
	case PT_R7:
		val = task->context.regs.gpr[PT_R7];
		break;
	case PT_R8:
		val = task->context.regs.gpr[PT_R8];
		break;
	case PT_R9:
		val = task->context.regs.gpr[PT_R9];
		break;
	case PT_R10:
		val = task->context.regs.gpr[PT_R10];
		break;
	case PT_R11:
		val = task->context.regs.gpr[PT_R11];
		break;
	case PT_R12:
		val = task->context.regs.gpr[PT_R12];
		break;
	case PT_R13:
		val = task->context.regs.gpr[PT_R13];
		break;
	case PT_R14:
		val = task->context.regs.gpr[PT_R14];
		break;
	case PT_R15:
		val = task->context.regs.gpr[PT_R15];
		break;
	case PT_R16:
		val = task->context.regs.gpr[PT_R16];
		break;
	case PT_R17:
		val = task->context.regs.gpr[PT_R17];
		break;
	case PT_R18:
		val = task->context.regs.gpr[PT_R18];
		break;
	case PT_R19:
		val = task->context.regs.gpr[PT_R19];
		break;
	case PT_R20:
		val = task->context.regs.gpr[PT_R20];
		break;
	case PT_R21:
		val = task->context.regs.gpr[PT_R21];
		break;
	case PT_R22:
		val = task->context.regs.gpr[PT_R22];
		break;
	case PT_R23:
		val = task->context.regs.gpr[PT_R23];
		break;
	case PT_R24:
		val = task->context.regs.gpr[PT_R24];
		break;
	case PT_R25:
		val = task->context.regs.gpr[PT_R25];
		break;
	case PT_R26:
		val = task->context.regs.gpr[PT_R26];
		break;
	case PT_R27:
		val = task->context.regs.gpr[PT_R27];
		break;
	case PT_R28:
		val = task->context.regs.gpr[PT_R28];
		break;
	case PT_R29:
		val = task->context.regs.gpr[PT_R29];
		break;
	case PT_R30:
		val = task->context.regs.gpr[PT_R30];
		break;
	case PT_R31:
		val = task->context.regs.gpr[PT_R31];
		break;
	case PT_NIP:
		val = task->context.regs.nip;
		break;
	case PT_MSR:
		val = task->context.regs.msr;
		break;
	case PT_ORIG_R3:
		val = task->context.regs.orig_gpr3;
		break;
	case PT_CTR:
		val = task->context.regs.ctr;
		break;
	case PT_LNK:
		val = task->context.regs.link;
		break;
	case PT_XER:
		val = task->context.regs.xer;
		break;
	case PT_CCR:
		val = task->context.regs.ccr;
		break;
#ifndef __powerpc64__
	case PT_MQ:
		val = task->context.regs.mq;
		break;
#else
	case PT_SOFTE:
		val = task->context.regs.softe;
		break;
#endif
	case PT_TRAP:
		val = task->context.regs.trap;
		break;
	case PT_DAR:
		val = task->context.regs.dar;
		break;
	case PT_DSISR:
		val = task->context.regs.dsisr;
		break;
	case PT_RESULT:
		val = task->context.regs.result;
		break;
	default:
		abort();
	}
	return fix_machine(task, val);
}

