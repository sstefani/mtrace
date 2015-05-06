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

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <inttypes.h>

#include "common.h"
#include "backend.h"
#include "debug.h"
#include "dwarf.h"
#include "task.h"

#define R_LR		65
#define R_CTR		66
#define R_CR0		68
#define R_CR1		69
#define R_CR2		70
#define R_CR3		71
#define R_CR4		72
#define R_XER		76
#define R_VR0		77
#define R_VRSAVE	109
#define R_VSCR		110
#define R_SPEFSCR	112
#define R_FRAME_POINTER	113

enum dwarf_ppc_regnum {
	DWARF_PPC_R0,
	DWARF_PPC_R1,	/* called STACK_POINTER in gcc */
	DWARF_PPC_R2,
	DWARF_PPC_R3,
	DWARF_PPC_R4,
	DWARF_PPC_R5,
	DWARF_PPC_R6,
	DWARF_PPC_R7,
	DWARF_PPC_R8,
	DWARF_PPC_R9,
	DWARF_PPC_R10,
	DWARF_PPC_R11,	/* called STATIC_CHAIN in gcc */
	DWARF_PPC_R12,
	DWARF_PPC_R13,
	DWARF_PPC_R14,
	DWARF_PPC_R15,
	DWARF_PPC_R16,
	DWARF_PPC_R17,
	DWARF_PPC_R18,
	DWARF_PPC_R19,
	DWARF_PPC_R20,
	DWARF_PPC_R21,
	DWARF_PPC_R22,
	DWARF_PPC_R23,
	DWARF_PPC_R24,
	DWARF_PPC_R25,
	DWARF_PPC_R26,
	DWARF_PPC_R27,
	DWARF_PPC_R28,
	DWARF_PPC_R29,
	DWARF_PPC_R30,
	DWARF_PPC_R31,	/* called HARD_FRAME_POINTER in gcc */
	DWARF_PPC_LR,	/* Link Register */
	DWARF_PPC_CTR,	/* Count Register */
	DWARF_PPC_CR0,	/* Condition Register */
	DWARF_PPC_CR1,
	DWARF_PPC_CR2,
	DWARF_PPC_CR3,
	DWARF_PPC_CR4,
	DWARF_PPC_XER,	/* Fixed-Point Status and Control Register */
	DWARF_PPC_VR0,
	DWARF_PPC_VRSAVE,
	DWARF_PPC_VSCR,
	DWARF_PPC_FPSCR,
	DWARF_PPC_FRAME_POINTER,
};

static const uint8_t dwarf_to_regnum_map[] = {
	[DWARF_PPC_R0] = PT_R0 + 1,
	[DWARF_PPC_R1] = PT_R1 + 1,
	[DWARF_PPC_R2] = PT_R2 + 1,
	[DWARF_PPC_R3] = PT_R3 + 1,
	[DWARF_PPC_R4] = PT_R4 + 1,
	[DWARF_PPC_R5] = PT_R5 + 1,
	[DWARF_PPC_R6] = PT_R6 + 1,
	[DWARF_PPC_R7] = PT_R7 + 1,
	[DWARF_PPC_R8] = PT_R8 + 1,
	[DWARF_PPC_R9] = PT_R9 + 1,
	[DWARF_PPC_R10] = PT_R10 + 1,
	[DWARF_PPC_R11] = PT_R11 + 1,
	[DWARF_PPC_R12] = PT_R12 + 1,
	[DWARF_PPC_R13] = PT_R13 + 1,
	[DWARF_PPC_R14] = PT_R14 + 1,
	[DWARF_PPC_R15] = PT_R15 + 1,
	[DWARF_PPC_R16] = PT_R16 + 1,
	[DWARF_PPC_R17] = PT_R17 + 1,
	[DWARF_PPC_R18] = PT_R18 + 1,
	[DWARF_PPC_R19] = PT_R19 + 1,
	[DWARF_PPC_R20] = PT_R20 + 1,
	[DWARF_PPC_R21] = PT_R21 + 1,
	[DWARF_PPC_R22] = PT_R22 + 1,
	[DWARF_PPC_R23] = PT_R23 + 1,
	[DWARF_PPC_R24] = PT_R24 + 1,
	[DWARF_PPC_R25] = PT_R25 + 1,
	[DWARF_PPC_R26] = PT_R26 + 1,
	[DWARF_PPC_R27] = PT_R27 + 1,
	[DWARF_PPC_R28] = PT_R28 + 1,
	[DWARF_PPC_R29] = PT_R29 + 1,
	[DWARF_PPC_R30] = PT_R30 + 1,
	[DWARF_PPC_R31] = PT_R31 + 1,
	[DWARF_PPC_LR] = PT_LNK + 1,
	[DWARF_PPC_CTR] = PT_CTR + 1,
	[DWARF_PPC_CR0] = PT_CCR + 1,
	[DWARF_PPC_CR1] = 0,
	[DWARF_PPC_CR2] = 0,
	[DWARF_PPC_CR3] = 0,
	[DWARF_PPC_CR4] = 0,
	[DWARF_PPC_XER] = PT_XER + 1,
	[DWARF_PPC_VR0] = 0,
	[DWARF_PPC_VRSAVE] = 0,
	[DWARF_PPC_VSCR] = 0,
	[DWARF_PPC_FPSCR] = 0,
	[DWARF_PPC_FRAME_POINTER] = 0,
};

int dwarf_arch_init(struct dwarf_addr_space *as)
{
	as->num_regs = ARRAY_SIZE(dwarf_to_regnum_map);

	as->ip_reg = as->num_regs;	/* not in dwarf, invalid register */
	as->ret_reg = DWARF_PPC_R1;

	return 0;
}

int dwarf_arch_init_unwind(struct dwarf_addr_space *as)
{
	struct dwarf_cursor *c = &as->cursor;
	unsigned int i;

	for(i = DWARF_PPC_R0; i <= DWARF_PPC_R31; ++i)
		c->loc[i] = DWARF_REG_LOC(i);

	c->loc[DWARF_PPC_LR] = DWARF_REG_LOC(DWARF_PPC_LR);
	c->loc[DWARF_PPC_CTR] = DWARF_REG_LOC(DWARF_PPC_CTR);
	c->loc[DWARF_PPC_CR0] = DWARF_REG_LOC(DWARF_PPC_CR0);
	c->loc[DWARF_PPC_CR1] = DWARF_REG_LOC(DWARF_PPC_CR1);
	c->loc[DWARF_PPC_CR2] = DWARF_REG_LOC(DWARF_PPC_CR2);
	c->loc[DWARF_PPC_CR3] = DWARF_REG_LOC(DWARF_PPC_CR3);
	c->loc[DWARF_PPC_CR4] = DWARF_REG_LOC(DWARF_PPC_CR4);
	c->loc[DWARF_PPC_XER] = DWARF_REG_LOC(DWARF_PPC_XER);
	c->loc[DWARF_PPC_VR0] = DWARF_REG_LOC(DWARF_PPC_VR0);
	c->loc[DWARF_PPC_VRSAVE] = DWARF_REG_LOC(DWARF_PPC_VRSAVE);
	c->loc[DWARF_PPC_VSCR] = DWARF_REG_LOC(DWARF_PPC_VSCR);
	c->loc[DWARF_PPC_FPSCR] = DWARF_REG_LOC(DWARF_PPC_FPSCR);
	c->loc[DWARF_PPC_FRAME_POINTER] = DWARF_REG_LOC(DWARF_PPC_FRAME_POINTER);

	c->ip = fetch_reg(as->task, PT_LNK);
	c->cfa = fetch_reg(as->task, PT_R1);

	c->use_prev_instr = 0;

	return 0;
}

static int is_signal_frame(struct dwarf_cursor *c)
{
	return c->dci.signal_frame;
}

#define	BACK_CHAIN	0
#define	LR_SAVE		1

int dwarf_arch_step(struct dwarf_addr_space *as)
{
	struct dwarf_cursor *c = &as->cursor;
	arch_addr_t cfa;
	int ret;

	if (is_signal_frame(c))
		return -DWARF_EBADFRAME;

	if ((ret = dwarf_get(as, DWARF_MEM_LOC(c->cfa + BACK_CHAIN * DWARF_ADDR_SIZE(as)), &cfa)) < 0) {
	      debug(DEBUG_DWARF, "Unable to retrieve CFA from back chain in stack frame - %d", ret);
	      return ret;
	}

	if (cfa <= c->cfa || cfa - c->cfa > 128 * 1024)
		return -DWARF_EBADFRAME;

	c->cfa = cfa;

	if ((ret = dwarf_get(as, DWARF_MEM_LOC(c->cfa + LR_SAVE * DWARF_ADDR_SIZE(as)), &c->ip)) < 0) {
	      debug(DEBUG_DWARF, "Unable to retrieve IP from lr save in stack frame - %d", ret);
	      return ret;
	}

	return 0;
}

int dwarf_arch_map_reg(struct dwarf_addr_space *as, unsigned int reg)
{
	int regnum;

	if (reg >= ARRAY_SIZE(dwarf_to_regnum_map))
		return -DWARF_EBADREG;

	regnum = dwarf_to_regnum_map[reg];
	if (!regnum)
		return -DWARF_EBADREG;

	return regnum -1;
}

unsigned int dwarf_to_regnum(unsigned int num)
{
	if (num < 32)
		return DWARF_PPC_R0 + num;

	switch(num) {
	case R_LR:
		return DWARF_PPC_LR;
	case R_CTR:
		return DWARF_PPC_CTR;
	case R_CR0:
		return DWARF_PPC_CR0;
	case R_CR1:
		return DWARF_PPC_CR1;
	case R_CR2:
		return DWARF_PPC_CR2;
	case R_CR3:
		return DWARF_PPC_CR3;
	case R_CR4:
		return DWARF_PPC_CR4;
	case R_XER:
		return DWARF_PPC_XER;
	case R_VR0:
		return DWARF_PPC_VR0;
	case R_VRSAVE:
		return DWARF_PPC_VRSAVE;
	case R_VSCR:
		return DWARF_PPC_VSCR;
	case R_SPEFSCR:
		return DWARF_PPC_FPSCR;
	case R_FRAME_POINTER:
		return DWARF_PPC_FRAME_POINTER;
	default:
		break;
	}
	return ~0;
}

