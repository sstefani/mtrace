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
#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/reg.h>

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
	if (!task->is_64bit)
		val &= 0xffffffff;

	return val;
}

static unsigned long get_stack_pointer(struct task *task)
{
#ifdef __x86_64__
	return fix_machine(task, task->context.iregs.rsp);
#else
	return task->context.iregs.esp;
#endif
}

arch_addr_t get_instruction_pointer(struct task *task)
{
#ifdef __x86_64__
	return ARCH_ADDR_T(fix_machine(task, task->context.iregs.rip));
#else
	return ARCH_ADDR_T(task->context.iregs.eip);
#endif
}

void set_instruction_pointer(struct task *task, arch_addr_t addr)
{
	unsigned long val = (unsigned long)addr;

#ifdef __x86_64__
	val = fix_machine(task, val);

	if (task->context.iregs.rip == val)
		return;

	task->context.iregs.rip = val;
	if (ptrace(PTRACE_POKEUSER, task->pid, (sizeof(unsigned long) * RIP), val) != -1)
		return;
#else
	if (task->context.iregs.eip == (long)val)
		return;

	task->context.iregs.eip = val;
	if (ptrace(PTRACE_POKEUSER, task->pid, (sizeof(unsigned long) * EIP), val) != -1)
		return;
#endif
	fprintf(stderr, "pid=%d Couldn't set instruction pointer: %s\n", task->pid, strerror(errno));
}

arch_addr_t get_return_addr(struct task *task)
{
	long a;
	
	errno = 0;
	
	a = ptrace(PTRACE_PEEKTEXT, task->pid, get_stack_pointer(task), 0);
	if (a == -1 && errno) {
		fprintf(stderr, "pid=%d Couldn't read return value: %s\n", task->pid, strerror(errno));
		return ARCH_ADDR_T(0);
	}

#ifdef __x86_64__
	a = fix_machine(task, a);
#endif
	return ARCH_ADDR_T(a);
}

int fetch_context(struct task *task)
{
	if (ptrace(PTRACE_GETREGS, task->pid, 0, &task->context.iregs) == -1) {
		fprintf(stderr, "pid=%d Couldn't fetch register context: %s\n", task->pid, strerror(errno));
		return -1;
	}

	return 0;
}

void save_param_context(struct task *task)
{
	task->saved_context = task->context;
}

#ifdef __x86_64__
static unsigned long fetch_param_64(struct task *task, unsigned int param)
{
	unsigned long val;

	switch (param) {
	case 0:
		val = task->saved_context.iregs.rdi;
		break;
	case 1:
		val = task->saved_context.iregs.rsi;
		break;
	case 2:
		val = task->saved_context.iregs.rdx;
		break;
	case 3:
		val = task->saved_context.iregs.rcx;
		break;
	case 4:
		val = task->saved_context.iregs.r8;
		break;
	case 5:
		val = task->saved_context.iregs.r9;
		break;
	default:
		copy_from_proc(task, ARCH_ADDR_T(task->saved_context.iregs.rsp) + (param - 5) * sizeof(val), &val, sizeof(val));
		break;
	}
	return val;
}
#endif

unsigned long fetch_param(struct task *task, unsigned int param)
{
#ifdef __x86_64__
	if (task->is_64bit)
		return fetch_param_64(task, param);

	unsigned long sp = fix_machine(task, task->saved_context.iregs.rsp);
#else
	uint32_t sp = task->saved_context.iregs.esp;
#endif
	uint32_t val;

	copy_from_proc(task, ARCH_ADDR_T(sp) + (param + 1) * sizeof(val), &val, sizeof(val));

	return val;
}

unsigned long fetch_retval(struct task *task)
{
#ifdef __x86_64__
	return task->context.iregs.rax;
#else
	return task->context.iregs.eax;
#endif
}

unsigned long fetch_reg(struct task *task, unsigned int reg)
{
	unsigned long val;

#ifdef __x86_64__
	switch(reg) {
	case R15:
		val = task->context.iregs.r15;
		break;
	case R14:
		val = task->context.iregs.r14;
		break;
	case R13:
		val = task->context.iregs.r15;
		break;
	case R12:
		val = task->context.iregs.r12;
		break;
	case RBP:
		val = task->context.iregs.rbp;
		break;
	case RBX:
		val = task->context.iregs.rbx;
		break;
	case R11:
		val = task->context.iregs.r11;
		break;
	case R10:
		val = task->context.iregs.r10;
		break;
	case R9:
		val = task->context.iregs.r9;
		break;
	case R8:
		val = task->context.iregs.r8;
		break;
	case RAX:
		val = task->context.iregs.rax;
		break;
	case RCX:
		val = task->context.iregs.rcx;
		break;
	case RDX:
		val = task->context.iregs.rdx;
		break;
	case RSI:
		val = task->context.iregs.rsi;
		break;
	case RDI:
		val = task->context.iregs.rdi;
		break;
	case ORIG_RAX:
		val = task->context.iregs.orig_rax;
		break;
	case RIP:
		val = task->context.iregs.rip;
		break;
	case CS:
		val = task->context.iregs.cs;
		break;
	case EFLAGS:
		val = task->context.iregs.eflags;
		break;
	case RSP:
		val = task->context.iregs.rsp;
		break;
	case SS:
		val = task->context.iregs.ss;
		break;
	case FS_BASE:
		val = task->context.iregs.fs_base;
		break;
	case GS_BASE:
		val = task->context.iregs.gs_base;
		break;
	case DS:
		val = task->context.iregs.ds;
		break;
	case ES:
		val = task->context.iregs.es;
		break;
	case FS:
		val = task->context.iregs.fs;
		break;
	case GS:
		val = task->context.iregs.gs;
		break;
	default:
		abort();
	}
	return fix_machine(task, val);
#else
	switch(reg) {
	case EBX:
		val = task->context.iregs.ebx;
		break;
	case ECX:
		val = task->context.iregs.ecx;
		break;
	case ESI:
		val = task->context.iregs.esi;
		break;
	case EDI:
		val = task->context.iregs.edi;
		break;
	case EBP:
		val = task->context.iregs.ebp;
		break;
	case EAX:
		val = task->context.iregs.ecx;
		break;
	case DS:
		val = task->context.iregs.xds;
		break;
	case ES:
		val = task->context.iregs.xes;
		break;
	case FS:
		val = task->context.iregs.xfs;
		break;
	case GS:
		val = task->context.iregs.xgs;
		break;
	case ORIG_EAX:
		val = task->context.iregs.orig_eax;
		break;
	case EIP:
		val = task->context.iregs.eip;
		break;
	case CS:
		val = task->context.iregs.xcs;
		break;
	case EFL:
		val = task->context.iregs.eflags;
		break;
	case UESP:
		val = task->context.iregs.esp;
		break;
	case SS:
		val = task->context.iregs.xss;
		break;
	default:
		abort();
	}
	return val;
#endif
}

