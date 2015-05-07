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
#include <string.h>
#include <inttypes.h>
#include <unistd.h>

#include "config.h"

#include "common.h"
#include "backend.h"
#include "debug.h"
#include "dwarf.h"
#include "library.h"
#include "task.h"

#define R_15	15
#define R_SPSR	128

#define	ARM_EXTABLE_ENTRY_SIZE	8

#define ARM_EXBUF_START(x)	(((x) >> 4) & 0x0f)
#define ARM_EXBUF_COUNT(x)	((x) & 0x0f)
#define ARM_EXBUF_END(x)	(ARM_EXBUF_START(x) + ARM_EXBUF_COUNT(x))

#define ARM_EXIDX_CANT_UNWIND	0x00000001
#define ARM_EXIDX_COMPACT	0x80000000

#define ARM_EXTBL_OP_FINISH	0xb0

typedef enum arm_exbuf_cmd {
	ARM_EXIDX_CMD_FINISH,
	ARM_EXIDX_CMD_DATA_PUSH,
	ARM_EXIDX_CMD_DATA_POP,
	ARM_EXIDX_CMD_REG_POP,
	ARM_EXIDX_CMD_REG_TO_SP,
	ARM_EXIDX_CMD_VFP_POP,
	ARM_EXIDX_CMD_WREG_POP,
	ARM_EXIDX_CMD_WCGR_POP,
	ARM_EXIDX_CMD_RESERVED,
	ARM_EXIDX_CMD_REFUSED,
} arm_exbuf_cmd_t;

struct arm_exbuf_data {
	arm_exbuf_cmd_t cmd;
	uint32_t data;
};

enum arm_exbuf_cmd_flags {
	ARM_EXIDX_VFP_SHIFT_16 = 1 << 16,
	ARM_EXIDX_VFP_DOUBLE = 1 << 17,
};

enum dwarf_ppc_regnum {
	DWARF_ARM_R0,
	DWARF_ARM_R1,
	DWARF_ARM_R2,
	DWARF_ARM_R3,
	DWARF_ARM_R4,
	DWARF_ARM_R5,
	DWARF_ARM_R6,
	DWARF_ARM_R7,
	DWARF_ARM_R8,
	DWARF_ARM_R9,
	DWARF_ARM_R10,
	DWARF_ARM_FP,
	DWARF_ARM_IP,
	DWARF_ARM_SP,
	DWARF_ARM_LR,
	DWARF_ARM_PC,
	DWARF_ARM_CPSR,
};

static const uint8_t dwarf_to_regnum_map[] = {
	[DWARF_ARM_R0] = offsetof(struct pt_regs, ARM_r0),
	[DWARF_ARM_R1] = offsetof(struct pt_regs, ARM_r1),
	[DWARF_ARM_R2] = offsetof(struct pt_regs, ARM_r2),
	[DWARF_ARM_R3] = offsetof(struct pt_regs, ARM_r3),
	[DWARF_ARM_R4] = offsetof(struct pt_regs, ARM_r4),
	[DWARF_ARM_R5] = offsetof(struct pt_regs, ARM_r5),
	[DWARF_ARM_R6] = offsetof(struct pt_regs, ARM_r6),
	[DWARF_ARM_R7] = offsetof(struct pt_regs, ARM_r7),
	[DWARF_ARM_R8] = offsetof(struct pt_regs, ARM_r8),
	[DWARF_ARM_R9] = offsetof(struct pt_regs, ARM_r9),
	[DWARF_ARM_R10] = offsetof(struct pt_regs, ARM_r10),
	[DWARF_ARM_FP] = offsetof(struct pt_regs, ARM_fp),
	[DWARF_ARM_IP] = offsetof(struct pt_regs, ARM_ip),
	[DWARF_ARM_SP] = offsetof(struct pt_regs, ARM_sp),
	[DWARF_ARM_LR] = offsetof(struct pt_regs, ARM_lr),
	[DWARF_ARM_PC] = offsetof(struct pt_regs, ARM_pc),
	[DWARF_ARM_CPSR] = offsetof(struct pt_regs, ARM_cpsr),
};

int dwarf_arch_init(struct dwarf_addr_space *as)
{
	as->num_regs = ARRAY_SIZE(dwarf_to_regnum_map);

	as->ip_reg = DWARF_ARM_PC;
	as->ret_reg = DWARF_ARM_SP;

	return 0;
}

int dwarf_arch_init_unwind(struct dwarf_addr_space *as)
{
	struct dwarf_cursor *c = &as->cursor;
	unsigned int i;

	for(i = DWARF_ARM_R0; i <= DWARF_ARM_R10; ++i)
		c->loc[i] = DWARF_REG_LOC(i);

	c->loc[DWARF_ARM_FP] = DWARF_REG_LOC(DWARF_ARM_FP);
	c->loc[DWARF_ARM_IP] = DWARF_REG_LOC(DWARF_ARM_IP);
	c->loc[DWARF_ARM_SP] = DWARF_REG_LOC(DWARF_ARM_SP);
	c->loc[DWARF_ARM_LR] = DWARF_REG_LOC(DWARF_ARM_LR);
	c->loc[DWARF_ARM_PC] = DWARF_REG_LOC(DWARF_ARM_PC);
	c->loc[DWARF_ARM_CPSR] = DWARF_REG_LOC(DWARF_ARM_CPSR);

	c->ip = fetch_reg(c->task, offsetof(struct pt_regs, ARM_pc));
	c->cfa = fetch_reg(c->task, offsetof(struct pt_regs, ARM_sp));

	c->use_prev_instr = 0;

	return 0;
}

static int is_signal_frame(struct dwarf_cursor *c)
{
	return c->dci.signal_frame;
}

int dwarf_arch_map_reg(struct dwarf_addr_space *as, unsigned int reg)
{
	if (reg >= ARRAY_SIZE(dwarf_to_regnum_map))
		return -DWARF_EBADREG;

	return dwarf_to_regnum_map[reg];
}

unsigned int dwarf_to_regnum(unsigned int num)
{
	if (num == R_SPSR)
		return DWARF_ARM_CPSR;

	if (num <= R_15)
		return num;

	return ~0;
}

static inline int access_mem(struct dwarf_addr_space *as, arch_addr_t addr, void *valp, size_t size)
{
#ifdef DEBUG
	if (as) {
		struct dwarf_cursor *c = &as->cursor;
		struct library *lib = c->lib;

		if (addr < ARCH_ADDR_T(lib->image_addr))
			fatal("invalid access mem: addr %#lx < %p", addr, lib->image_addr);
		if (addr >= ARCH_ADDR_T(lib->image_addr + lib->load_size))
			fatal("invalid access mem: addr %#lx >= %p", addr, lib->image_addr + lib->load_size);
	}
#endif

	memcpy(valp, (void *)addr, size);
	return 0;
}

static int prel31_to_addr(struct dwarf_addr_space *as, arch_addr_t prel31, arch_addr_t *val)
{
	int32_t offset;

	if (access_mem(as, prel31, &offset, sizeof(offset)) < 0)
		return -DWARF_EINVAL;

	offset = (offset << 1) >> 1;

	*val = prel31 + offset;

	return 0;
}

static int arm_exidx_apply_cmd(struct dwarf_addr_space *as, struct arm_exbuf_data *edata)
{
	struct dwarf_cursor *c = &as->cursor;
	arch_addr_t ip;
	unsigned int i;

	switch(edata->cmd) {
	case ARM_EXIDX_CMD_FINISH:
		/* Set LR to PC if not set already.	*/
		if (DWARF_IS_NULL_LOC(c->loc[DWARF_ARM_PC]))
			c->loc[DWARF_ARM_PC] = c->loc[DWARF_ARM_LR];
		/* Set IP.	*/
		if (dwarf_get(as, c->loc[DWARF_ARM_PC], &ip) < 0)
			return -DWARF_EINVAL;
		c->ip = ip;
		break;
	case ARM_EXIDX_CMD_DATA_PUSH:
		debug(DEBUG_DWARF, "vsp = vsp - %d", edata->data);
		c->cfa -= edata->data;
		break;
	case ARM_EXIDX_CMD_DATA_POP:
		debug(DEBUG_DWARF, "vsp = vsp + %d", edata->data);
		c->cfa += edata->data;
		break;
	case ARM_EXIDX_CMD_REG_POP:
		for (i = 0; i < 16; i++) {
			if (edata->data & (1 << i)) {
				debug(DEBUG_DWARF, "pop {r%d}", i);
				c->loc[DWARF_ARM_R0 + i] = DWARF_MEM_LOC(c->cfa);
				c->cfa += 4;
			}
		}
		/* Set cfa in case the SP got popped. */
		if (edata->data & (1 << 13)) {
			if (dwarf_get(as, c->loc[DWARF_ARM_SP], &c->cfa) < 0)
				return -DWARF_EINVAL;
		}
		break;
	case ARM_EXIDX_CMD_REG_TO_SP:
		assert (edata->data < 16);

		debug(DEBUG_DWARF, "vsp = r%d", edata->data);

		c->loc[DWARF_ARM_SP] = c->loc[DWARF_ARM_R0 + edata->data];

		if (dwarf_get(as, c->loc[DWARF_ARM_SP], &c->cfa) < 0)
			return -DWARF_EINVAL;

		break;
	case ARM_EXIDX_CMD_VFP_POP:
		/* Skip VFP registers, but be sure to adjust stack */
		for (i = ARM_EXBUF_START(edata->data); i <= ARM_EXBUF_END(edata->data); i++)
			c->cfa += 8;
		if (!(edata->data & ARM_EXIDX_VFP_DOUBLE))
			c->cfa += 4;
		break;
	case ARM_EXIDX_CMD_WREG_POP:
		for (i = ARM_EXBUF_START(edata->data); i <= ARM_EXBUF_END(edata->data); i++)
			c->cfa += 8;
		break;
	case ARM_EXIDX_CMD_WCGR_POP:
		for (i = 0; i < 4; i++) {
			if (edata->data & (1 << i))
				c->cfa += 4;
		}
		break;
	case ARM_EXIDX_CMD_REFUSED:
	case ARM_EXIDX_CMD_RESERVED:
		return -DWARF_EINVAL;
	}
	return 0;
}

static int arm_exidx_decode(struct dwarf_addr_space *as, const uint8_t *buf, uint8_t len)
{
	const uint8_t *end = buf + len;
	int ret;
	struct arm_exbuf_data edata;

	assert(buf != NULL);
	assert(len > 0);

	while(buf < end) {
		uint8_t op = *buf++;

		if ((op & 0xc0) == 0x00) {
			edata.cmd = ARM_EXIDX_CMD_DATA_POP;
			edata.data = (((int)op & 0x3f) << 2) + 4;
		}
		else
		if ((op & 0xc0) == 0x40) {
			edata.cmd = ARM_EXIDX_CMD_DATA_PUSH;
			edata.data = (((int)op & 0x3f) << 2) + 4;
		}
		else
		if ((op & 0xf0) == 0x80) {
			uint8_t op2 = *buf++;

			if (op == 0x80 && op2 == 0x00)
				edata.cmd = ARM_EXIDX_CMD_REFUSED;
			else {
				edata.cmd = ARM_EXIDX_CMD_REG_POP;
				edata.data = ((op & 0xf) << 8) | op2;
				edata.data = edata.data << 4;
			}
		}
		else
		if ((op & 0xf0) == 0x90) {
			if (op == 0x9d || op == 0x9f)
				edata.cmd = ARM_EXIDX_CMD_RESERVED;
			else {
				edata.cmd = ARM_EXIDX_CMD_REG_TO_SP;
				edata.data = op & 0x0f;
			}
		}
		else
		if ((op & 0xf0) == 0xa0) {
			unsigned end = (op & 0x07);

			edata.data = (1 << (end + 1)) - 1;
			edata.data = edata.data << 4;
			if (op & 0x08)
				edata.data |= 1 << 14;
			edata.cmd = ARM_EXIDX_CMD_REG_POP;
		}
		else
		if (op == ARM_EXTBL_OP_FINISH) {
			edata.cmd = ARM_EXIDX_CMD_FINISH;
			buf = end;
		}
		else
		if (op == 0xb1) {
			uint8_t op2 = *buf++;

			if (op2 == 0 || (op2 & 0xf0))
				edata.cmd = ARM_EXIDX_CMD_RESERVED;
			else {
				edata.cmd = ARM_EXIDX_CMD_REG_POP;
				edata.data = op2 & 0x0f;
			}
		}
		else
		if (op == 0xb2) {
			uint32_t offset = 0;
			uint8_t byte, shift = 0;

			do {
				byte = *buf++;
				offset |= (byte & 0x7f) << shift;
				shift += 7;
			} while(byte & 0x80);

			edata.data = offset * 4 + 0x204;
			edata.cmd = ARM_EXIDX_CMD_DATA_POP;
		}
		else
		if (op == 0xb3 || op == 0xc8 || op == 0xc9) {
			edata.cmd = ARM_EXIDX_CMD_VFP_POP;
			edata.data = *buf++;
			if (op == 0xc8)
				edata.data |= ARM_EXIDX_VFP_SHIFT_16;
			if (op != 0xb3)
				edata.data |= ARM_EXIDX_VFP_DOUBLE;
		}
		else
		if ((op & 0xf8) == 0xb8 || (op & 0xf8) == 0xd0) {
			edata.cmd = ARM_EXIDX_CMD_VFP_POP;
			edata.data = 0x80 | (op & 0x07);
			if ((op & 0xf8) == 0xd0)
				edata.data |= ARM_EXIDX_VFP_DOUBLE;
		}
		else
		if (op >= 0xc0 && op <= 0xc5) {
			edata.cmd = ARM_EXIDX_CMD_WREG_POP;
			edata.data = 0xa0 | (op & 0x07);
		}
		else
		if (op == 0xc6) {
			edata.cmd = ARM_EXIDX_CMD_WREG_POP;
			edata.data = *buf++;
		}
		else
		if (op == 0xc7) {
			uint8_t op2 = *buf++;

			if (op2 == 0 || (op2 & 0xf0))
				edata.cmd = ARM_EXIDX_CMD_RESERVED;
			else {
				edata.cmd = ARM_EXIDX_CMD_WCGR_POP;
				edata.data = op2 & 0x0f;
			}
		}
		else
			edata.cmd = ARM_EXIDX_CMD_RESERVED;

		ret = arm_exidx_apply_cmd(as, &edata);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int arm_exidx_extract(struct dwarf_addr_space *as, arch_addr_t entry, uint8_t *buf)
{
	int nbuf = 0;
	arch_addr_t addr;
	uint32_t data;

#ifdef DEBUG
	if (prel31_to_addr(NULL, entry, &addr) < 0)
		return -DWARF_EINVAL;
#else
	addr = 0;
#endif

	/* An ARM unwind entry consists of a prel31 offset to the start of a
	   function followed by 31bits of data: 
	   * if set to 0x1: the function cannot be unwound (EXIDX_CANTUNWIND)
	   * if bit 31 is one: this is a table entry itself (ARM_EXIDX_COMPACT)
	   * if bit 31 is zero: this is a prel31 offset of the start of the
	     table entry for this function */
	if (access_mem(as, entry + 4, &data, sizeof(data)) < 0)
		return -DWARF_EINVAL;

	if (data == ARM_EXIDX_CANT_UNWIND) {
		debug(DEBUG_DWARF, "can't unwind");
		return -DWARF_STOPUNWIND;
	}
	else
	if (data & ARM_EXIDX_COMPACT) {
		debug(DEBUG_DWARF, "%#lx compact model %d [%8.8x]", addr, (data >> 24) & 0x7f, data);
		buf[nbuf++] = data >> 16;
		buf[nbuf++] = data >> 8;
		buf[nbuf++] = data;
	}
	else {
		arch_addr_t extbl_data;
		unsigned int n_table_words;

		if (prel31_to_addr(as, entry + 4, &extbl_data) < 0)
			return -DWARF_EINVAL;


		if (access_mem(as, extbl_data, &data, sizeof(data)) < 0)
			return -DWARF_EINVAL;

		if (data & ARM_EXIDX_COMPACT) {
			unsigned int pers = (data >> 24) & 0x0f;

			debug(DEBUG_DWARF, "%#lx compact model %d [%8.8x]", addr, pers, data);

			if (pers == 1 || pers == 2) {
				n_table_words = (data >> 16) & 0xff;
				extbl_data += 4;
			}
			else {
				n_table_words = 0;
				buf[nbuf++] = data >> 16;
			}
			buf[nbuf++] = data >> 8;
			buf[nbuf++] = data;
		}
		else {
			arch_addr_t pers;

			if (prel31_to_addr(as, extbl_data, &pers) < 0)
				return -DWARF_EINVAL;

			debug(DEBUG_DWARF, "%#lx Personality routine: %#lx", addr, pers);

			if (access_mem(as, extbl_data + 4, &data, sizeof(data)) < 0)
				return -DWARF_EINVAL;

			n_table_words = data >> 24;
			buf[nbuf++] = data >> 16;
			buf[nbuf++] = data >> 8;
			buf[nbuf++] = data;
			extbl_data += 8;
		}
		assert(n_table_words <= 5);

		unsigned j;

		for(j = 0; j < n_table_words; j++) {
			if (access_mem(as, extbl_data, &data, sizeof(data)) < 0)
				return -DWARF_EINVAL;
			extbl_data += 4;
			buf[nbuf++] = data >> 24;
			buf[nbuf++] = data >> 16;
			buf[nbuf++] = data >> 8;
			buf[nbuf++] = data >> 0;
		}
	}

	if (nbuf > 0 && buf[nbuf - 1] != ARM_EXTBL_OP_FINISH)
		buf[nbuf++] = ARM_EXTBL_OP_FINISH;

	return nbuf;
}

static unsigned long arm_search_unwind_table(struct dwarf_addr_space *as, arch_addr_t ip, void *exidx_data, unsigned long exidx_len)
{
	struct dwarf_cursor *c = &as->cursor;
	struct library *lib = c->lib;
	unsigned long map_offset = (unsigned long)lib->image_addr + lib->load_offset - lib->load_addr;
	unsigned long lo, hi, e, f;
	arch_addr_t val;

	hi = exidx_len / ARM_EXTABLE_ENTRY_SIZE;
	if (!hi)
		return 0;

	lo = 0;
	f = 0;

	do {
		unsigned long mid = (lo + hi) / 2;

		e = (unsigned long)exidx_data + mid * ARM_EXTABLE_ENTRY_SIZE;

		if (prel31_to_addr(NULL, e, &val) < 0)
			return -DWARF_EINVAL;

		val -= map_offset;

		if (ip < val)
			hi = mid;
		else {
			f = e;
			lo = mid + 1;
		}
	} while(lo < hi);

	return f;
}

static int arm_exidx_step(struct dwarf_addr_space *as)
{
	struct dwarf_cursor *c = &as->cursor;
	struct library *lib = c->lib;
	arch_addr_t old_ip, old_cfa, entry;
	uint8_t buf[32];
	int ret;

	if (!lib)
		return -DWARF_ENOINFO;

	old_ip = c->ip;
	old_cfa = c->cfa;

	/* mark PC unsaved */
	c->loc[DWARF_ARM_PC] = DWARF_NULL_LOC;

	entry = arm_search_unwind_table(as, c->ip, lib->exidx_data, lib->exidx_len);
	if (!entry)
		return -DWARF_ENOINFO;

	ret = arm_exidx_extract(as, entry, buf);
	if (ret <= 0)
		return ret;

	ret = arm_exidx_decode(as, buf, ret);
	if (ret)
		return ret;

	if (c->ip == old_ip && c->cfa == old_cfa) {
		debug(DEBUG_DWARF, "ip and cfa unchanged; stopping here (ip=0x%lx)\n", c->ip);
		return -DWARF_EBADFRAME;
	}

	if (!c->ip)
		return -DWARF_EINVAL;

	return 0;
}

static int arm_frame_step(struct dwarf_addr_space *as)
{
	struct dwarf_cursor *c = &as->cursor;
	struct dwarf_loc ip_loc, fp_loc;
	arch_addr_t instr, ip, fp, nframe;
	int ret;

	if (dwarf_get(as, c->loc[DWARF_ARM_FP], &fp) < 0)
		return -DWARF_EBADFRAME;

	if (fp <= c->cfa || fp - c->cfa > 128 * 1024)
		return -DWARF_EBADFRAME;

	if (dwarf_get(as, DWARF_MEM_LOC(fp), &nframe) < 0)
		return -DWARF_EBADFRAME;

	ret = dwarf_locate_map(as, nframe - 8);
	if (ret)
		return -DWARF_ENOINFO;

	if (dwarf_get(as, DWARF_MEM_LOC(nframe - 8), &instr) < 0)
		return -DWARF_ENOINFO;

	if ((instr & 0xFFFFD800) == 0xE92DD800) {
		/* Standard APCS fp. */
		ip_loc = DWARF_MEM_LOC(fp - 4);
		fp_loc = DWARF_MEM_LOC(fp - 12);
	}
	else {
		/* Codesourcery optimized normal frame. */
		ip_loc = DWARF_MEM_LOC(fp);
		fp_loc = DWARF_MEM_LOC(fp - 4);
	}
		
	if (dwarf_get(as, ip_loc, &ip) < 0)
		return -DWARF_EBADFRAME;

	c->loc[DWARF_ARM_IP] = ip_loc;
	c->loc[DWARF_ARM_FP] = fp_loc;
	c->ip = ip;
	c->cfa = fp;

	debug(DEBUG_DWARF, "ip=%lx", c->ip);

	return 0;
}

int dwarf_arch_step(struct dwarf_addr_space *as)
{
	struct dwarf_cursor *c = &as->cursor;
	int ret;

	if (is_signal_frame(c))
		return -DWARF_EBADFRAME;

	ret = arm_exidx_step(as);
	if (ret) {
		if (ret == -DWARF_STOPUNWIND)
			return ret;
	}

	if (arm_frame_step(as) == 0)
		return 0;

	return -DWARF_EBADFRAME;
}

