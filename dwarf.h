/*
 * This file is part of mtrace-ng.
 * Copyright (C) 2018 Stefani Seibold <stefani@seibold.net>
 *  This file is based on the libunwind source
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

#ifndef _INC_DWARF_H
#define _INC_DWARF_H

#include <stdint.h>

#include "arch.h"
#include "common.h"
#include "forward.h"
#include "library.h"
#include "mtelf.h"

#define DWARF_LOC(r, t)		((struct dwarf_loc){ .val = (r), .type = (t) })

#define DWARF_GET_LOC(l)	((l).val)

#define DWARF_LOC_TYPE_MEM	0
#define DWARF_LOC_TYPE_REG	1
#define DWARF_LOC_TYPE_VAL	2

#define DWARF_NULL_LOC		DWARF_LOC(0, 0)
#define DWARF_MEM_LOC(m)	DWARF_LOC((m), DWARF_LOC_TYPE_MEM)
#define DWARF_REG_LOC(r)	DWARF_LOC((r), DWARF_LOC_TYPE_REG)
#define DWARF_VAL_LOC(v)	DWARF_LOC((v), DWARF_LOC_TYPE_VAL)

#define DWARF_IS_NULL_LOC(l)	({ struct dwarf_loc _l = (l); _l.val == 0 && _l.type == 0; })
#define DWARF_IS_MEM_LOC(l)	((l).type == DWARF_LOC_TYPE_MEM)
#define DWARF_IS_REG_LOC(l)	((l).type == DWARF_LOC_TYPE_REG)
#define DWARF_IS_VAL_LOC(l)	((l).type == DWARF_LOC_TYPE_VAL)

#define DWARF_ADDR_SIZE(as)	((as)->is_64bit ? 8 : 4)

#define DWARF_ENOMEM		1	/* out of memory */
#define DWARF_EBADREG		2	/* bad register number */
#define DWARF_EBADFRAME		3	/* bad frame */
#define DWARF_EINVAL		4	/* unsupported operation or bad value */
#define DWARF_EBADVERSION	5	/* unwind info has unsupported version */
#define DWARF_ENOINFO		6	/* no unwind info found */
#define DWARF_STOPUNWIND 	7

struct dwarf_cie_info {
	arch_addr_t start_ip;		/* first IP covered by this procedure */
	arch_addr_t ip_range;		/* ip range  covered by this procedure */
	arch_addr_t cie_instr_start;	/* start addr. of CIE "initial_instructions" */
	arch_addr_t cie_instr_end;	/* end addr. of CIE "initial_instructions" */
	arch_addr_t fde_instr_start;	/* start addr. of FDE "instructions" */
	arch_addr_t fde_instr_end;	/* end addr. of FDE "instructions" */
	arch_addr_t code_align;		/* code-alignment factor */
	arch_addr_t data_align;		/* data-alignment factor */
	arch_addr_t ret_addr_column;	/* column of return-address register */
	uint16_t abi;
	uint16_t tag;
	uint8_t fde_encoding;
	uint8_t lsda_encoding;
	unsigned int sized_augmentation:1;
	unsigned int have_abi_marker:1;
	unsigned int signal_frame:1;
};

struct dwarf_loc {
	unsigned long val;
	unsigned int type;
};

struct dwarf_cursor {
	struct task *task;
	arch_addr_t cfa;		/* canonical frame address; aka frame-/stack-pointer */
	arch_addr_t ip;			/* instruction pointer */
	arch_addr_t ret_addr_column;	/* column for return-address */
	unsigned int use_prev_instr:1;	/* use previous (= call) or current (= signal) instruction? */
	unsigned int valid:1;
	struct libref *libref;
	struct dwarf_cie_info dci;
	struct dwarf_loc *loc;
};

struct dwarf_addr_space {
	unsigned int is_64bit:1;
	struct dwarf_cursor cursor;
	unsigned int ip_reg;
	unsigned int ret_reg;
	unsigned int num_regs;
};

struct dwarf_eh_frame_hdr;

void *dwarf_init(int is_64bit);
void dwarf_destroy(struct dwarf_addr_space *as);
int dwarf_init_unwind(struct dwarf_addr_space *as, struct task *task);
int dwarf_step(struct dwarf_addr_space *as);

int dwarf_locate_map(struct dwarf_addr_space *as, arch_addr_t ip);

int dwarf_get(struct dwarf_addr_space *as, struct dwarf_loc loc, arch_addr_t *valp);

int dwarf_get_unwind_table(struct task *task, struct libref *libref);

int dwarf_arch_init(struct dwarf_addr_space *as);
int dwarf_arch_init_unwind(struct dwarf_addr_space *as);
int dwarf_arch_step(struct dwarf_addr_space *as);
int dwarf_arch_map_reg(struct dwarf_addr_space *as, unsigned int reg);
int dwarf_arch_check_call(struct dwarf_addr_space *as, arch_addr_t ip);

#ifdef DWARF_TO_REGNUM
unsigned int dwarf_to_regnum(unsigned int reg);
#else
static inline __attribute__((const)) unsigned int dwarf_to_regnum(unsigned int reg)
{
	return reg;
}
#endif

static inline arch_addr_t dwarf_get_ip(struct dwarf_addr_space *as)
{
	struct dwarf_cursor *c = &as->cursor;

	if (unlikely(!c->valid))
		return ARCH_ADDR_T(0);

	return c->ip;
}

static inline int dwarf_location_type(struct dwarf_addr_space *as)
{
	struct libref *libref = as->cursor.libref;

	if (!libref)
		return -1;

	return libref->type;
}
#endif

