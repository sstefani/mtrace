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

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/reg.h>

#include "common.h"
#include "backend.h"
#include "debug.h"
#include "dwarf.h"
#include "task.h"

struct arch_reg {
	unsigned int ip;
	unsigned int sp;
	unsigned int bp;
};

enum dwarf_x86_32_regnum {
	DWARF_X86_EAX,
	DWARF_X86_ECX,
	DWARF_X86_EDX,
	DWARF_X86_EBX,
	DWARF_X86_ESP,
	DWARF_X86_EBP,
	DWARF_X86_ESI,
	DWARF_X86_EDI,
	DWARF_X86_EIP,
};

#ifndef __x86_64__
static const uint8_t dwarf_to_regnum_map32[] = {
	[DWARF_X86_EAX] = EAX,
	[DWARF_X86_ECX] = ECX,
	[DWARF_X86_EDX] = EDX,
	[DWARF_X86_EBX] = EBX,
	[DWARF_X86_ESP] = UESP,
	[DWARF_X86_EBP] = EBP,
	[DWARF_X86_ESI] = ESI,
	[DWARF_X86_EDI] = EDI,
	[DWARF_X86_EIP] = EIP,
};
#else
static const uint8_t dwarf_to_regnum_map32[] = {
	[DWARF_X86_EAX] = RAX,
	[DWARF_X86_ECX] = RCX,
	[DWARF_X86_EDX] = RDX,
	[DWARF_X86_EBX] = RBX,
	[DWARF_X86_ESP] = RSP,
	[DWARF_X86_EBP] = RBP,
	[DWARF_X86_ESI] = RSI,
	[DWARF_X86_EDI] = RDI,
	[DWARF_X86_EIP] = RIP,
};

enum dwarf_x86_64_regnum {
	DWARF_X86_RAX,
	DWARF_X86_RDX,
	DWARF_X86_RCX,
	DWARF_X86_RBX,
	DWARF_X86_RSI,
	DWARF_X86_RDI,
	DWARF_X86_RBP,
	DWARF_X86_RSP,
	DWARF_X86_R8,
	DWARF_X86_R9,
	DWARF_X86_R10,
	DWARF_X86_R11,
	DWARF_X86_R12,
	DWARF_X86_R13,
	DWARF_X86_R14,
	DWARF_X86_R15,
	DWARF_X86_RIP,
};

static const uint8_t dwarf_to_regnum_map64[] = {
	[DWARF_X86_RAX] = RAX,
	[DWARF_X86_RDX] = RDX,
	[DWARF_X86_RCX] = RCX,
	[DWARF_X86_RBX] = RBX,
	[DWARF_X86_RSI] = RSI,
	[DWARF_X86_RDI] = RDI,
	[DWARF_X86_RBP] = RBP,
	[DWARF_X86_RSP] = RSP,
	[DWARF_X86_R8]  = R8,
	[DWARF_X86_R9]  = R9,
	[DWARF_X86_R10] = R10,
	[DWARF_X86_R11] = R11,
	[DWARF_X86_R12] = R12,
	[DWARF_X86_R13] = R13,
	[DWARF_X86_R14] = R14,
	[DWARF_X86_R15] = R15,
	[DWARF_X86_RIP] = RIP,
};

static const struct arch_reg arch_reg64 = {
	.ip = DWARF_X86_RIP,
	.sp = DWARF_X86_RSP,
	.bp = DWARF_X86_RBP,
};
#endif

static const struct arch_reg arch_reg32 = {
	.ip = DWARF_X86_EIP,
	.sp = DWARF_X86_ESP,
	.bp = DWARF_X86_EBP,
};

static int is_signal_frame(struct dwarf_cursor *c)
{
	return c->dci.signal_frame;
}

static int is_plt_entry(struct dwarf_addr_space *as)
{
#if 0
	struct dwarf_cursor *c = &as->cursor;
	uint8_t data[12];

	if (copy_from_proc(as->task, c->ip, data, sizeof(data)) != sizeof(data)) {
		debug(DEBUG_DWARF, "cannot access memory %#lx of pid %d", c->ip, as->task->pid);
		return 0;
	}

	if (data[0] == 0xff && data[1] == 0x25 && data[6] == 0x68 && data[11] == 0xe9)
		return 1;
#endif
	return 0;
}

int dwarf_arch_init(struct dwarf_addr_space *as)
{
#ifdef __x86_64__
	if (task_is_64bit(as->task)) {
		as->ip_reg = arch_reg64.ip;
		as->ret_reg = arch_reg64.sp;
		as->num_regs = ARRAY_SIZE(dwarf_to_regnum_map64);

		return 0;
	}
#endif
	as->ip_reg = arch_reg32.ip;
	as->ret_reg = arch_reg32.sp;
	as->num_regs = ARRAY_SIZE(dwarf_to_regnum_map32);

	return 0;
}

int dwarf_arch_init_unwind(struct dwarf_addr_space *as)
{
	struct dwarf_cursor *c = &as->cursor;

#ifdef __x86_64__
	if (task_is_64bit(as->task)) {
		c->loc[DWARF_X86_RAX] = DWARF_REG_LOC(DWARF_X86_RAX);
		c->loc[DWARF_X86_RDX] = DWARF_REG_LOC(DWARF_X86_RDX);
		c->loc[DWARF_X86_RCX] = DWARF_REG_LOC(DWARF_X86_RCX);
		c->loc[DWARF_X86_RBX] = DWARF_REG_LOC(DWARF_X86_RBX);
		c->loc[DWARF_X86_RSI] = DWARF_REG_LOC(DWARF_X86_RSI);
		c->loc[DWARF_X86_RDI] = DWARF_REG_LOC(DWARF_X86_RDI);
		c->loc[DWARF_X86_RBP] = DWARF_REG_LOC(DWARF_X86_RBP);
		c->loc[DWARF_X86_RSP] = DWARF_REG_LOC(DWARF_X86_RSP);
		c->loc[DWARF_X86_R8]  = DWARF_REG_LOC(DWARF_X86_R8);
		c->loc[DWARF_X86_R9]  = DWARF_REG_LOC(DWARF_X86_R9);
		c->loc[DWARF_X86_R10] = DWARF_REG_LOC(DWARF_X86_R10);
		c->loc[DWARF_X86_R11] = DWARF_REG_LOC(DWARF_X86_R11);
		c->loc[DWARF_X86_R12] = DWARF_REG_LOC(DWARF_X86_R12);
		c->loc[DWARF_X86_R13] = DWARF_REG_LOC(DWARF_X86_R13);
		c->loc[DWARF_X86_R14] = DWARF_REG_LOC(DWARF_X86_R14);
		c->loc[DWARF_X86_R15] = DWARF_REG_LOC(DWARF_X86_R15);
		c->loc[DWARF_X86_RIP] = DWARF_REG_LOC(DWARF_X86_RIP);

		c->ip = fetch_reg(as->task, RIP);
		c->cfa = fetch_reg(as->task, RSP);
	}
	else
#endif
	{
		c->loc[DWARF_X86_EAX] = DWARF_REG_LOC(DWARF_X86_EAX);
		c->loc[DWARF_X86_ECX] = DWARF_REG_LOC(DWARF_X86_ECX);
		c->loc[DWARF_X86_EDX] = DWARF_REG_LOC(DWARF_X86_EDX);
		c->loc[DWARF_X86_EBX] = DWARF_REG_LOC(DWARF_X86_EBX);
		c->loc[DWARF_X86_ESP] = DWARF_REG_LOC(DWARF_X86_ESP);
		c->loc[DWARF_X86_EBP] = DWARF_REG_LOC(DWARF_X86_EBP);
		c->loc[DWARF_X86_ESI] = DWARF_REG_LOC(DWARF_X86_ESI);
		c->loc[DWARF_X86_EDI] = DWARF_REG_LOC(DWARF_X86_EDI);
		c->loc[DWARF_X86_EIP] = DWARF_REG_LOC(DWARF_X86_EIP);

		c->ip = fetch_reg(as->task, dwarf_to_regnum_map32[DWARF_X86_EIP]);
		c->cfa = fetch_reg(as->task, dwarf_to_regnum_map32[DWARF_X86_ESP]);
	}

	c->use_prev_instr = 0;

	return 0;
}

int dwarf_arch_step(struct dwarf_addr_space *as)
{
	unsigned int i;
	arch_addr_t prev_cfa;
	struct dwarf_cursor *c = &as->cursor;
	const struct arch_reg *arch_reg;
	int ret;

#ifdef __x86_64__
	arch_reg = task_is_64bit(as->task) ? &arch_reg64 : &arch_reg32;
#else
	arch_reg = &arch_reg32;
#endif

	if (is_signal_frame(c))
		return -DWARF_EBADFRAME;

	if (DWARF_IS_NULL_LOC(c->loc[arch_reg->bp])) {
		c->ip = 0;
		return 0;
	}

	prev_cfa = c->cfa;

	if (is_plt_entry(as)) {
		debug(DEBUG_FUNCTION, "found plt entry");

		/* Like regular frame, CFA = SP+addrsz, RA = [CFA-addrsz], no regs saved. */
		c->loc[arch_reg->ip] = DWARF_MEM_LOC(c->cfa);
		c->cfa += DWARF_ADDR_SIZE(as);
	}
	else {
		struct dwarf_loc rbp_loc = c->loc[arch_reg->bp];

		/* Mark all registers unsaved */
		for (i = 0; i < as->num_regs; ++i)
			c->loc[i] = DWARF_NULL_LOC;

		arch_addr_t rbp;

		ret = dwarf_get(as, rbp_loc, &rbp);
		if (ret < 0)
			return ret;

		if (rbp > c->cfa && rbp - c->cfa <= 128 * 1024) {
			c->loc[arch_reg->bp] = DWARF_MEM_LOC(rbp);
			c->loc[arch_reg->ip] = DWARF_MEM_LOC(rbp + DWARF_ADDR_SIZE(as));
			c->cfa = rbp + DWARF_ADDR_SIZE(as) * 2;
			c->use_prev_instr = 1;
		}
	}

	if (c->cfa == prev_cfa)
		return -DWARF_EBADFRAME;

	c->ret_addr_column = arch_reg->ip;

	if (!DWARF_IS_NULL_LOC(c->loc[arch_reg->ip])) {
		ret = dwarf_get(as, c->loc[arch_reg->ip], &c->ip);
		if (ret < 0)
			return ret;

		debug(DEBUG_FUNCTION, "Frame Chain [IP=%#lx] = %#lx", DWARF_GET_LOC(c->loc[arch_reg->ip]), c->ip);
	}
	else
		c->ip = 0;

	return 0;
}

int dwarf_arch_map_reg(struct dwarf_addr_space *as, unsigned int reg)
{
#ifdef __x86_64__
	if (task_is_64bit(as->task)) {
		if (reg >= ARRAY_SIZE(dwarf_to_regnum_map64))
			return -DWARF_EBADREG;

		return dwarf_to_regnum_map64[reg];
	}
#endif
	if (reg >= ARRAY_SIZE(dwarf_to_regnum_map32))
		return -DWARF_EBADREG;

	return dwarf_to_regnum_map32[reg];
}

