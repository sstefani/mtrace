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

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "backend.h"
#include "breakpoint.h"
#include "common.h"
#include "mtelf.h"
#include "task.h"

#define COND_ALWAYS	0xe
#define COND_NV		0xf
#define FLAG_C		0x20000000

#define SUBMASK(x)		((1 << ((x) + 1)) - 1)
#define BIT(obj, st)		(((obj) >> (st)) & 1)
#define BITS(obj, st, fn)	(((obj) >> (st)) & SUBMASK((fn) - (st)))
#define SBITS(obj, st, fn)	(BITS(obj, st, fn) | (BIT(obj, fn) * ~ SUBMASK((fn) - (st))))

#define ARM_REG_SP	13
#define ARM_REG_LR	14
#define ARM_REG_PC	15
#define ARM_REG_CPSR	16

int is_64bit(struct mt_elf *mte)
{
	return 0;
}

static inline int bitcount(unsigned int n)
{
	return __builtin_popcount(n);
}

static inline int proc_read_8(struct task *task, uint32_t addr, uint8_t *dst)
{
	return copy_from_proc(task, addr, dst, sizeof(*dst));
}

static inline int proc_read_16(struct task *task, uint32_t addr, uint16_t *dst)
{
	return copy_from_proc(task, addr, dst, sizeof(*dst));
}

static inline int proc_read_32(struct task *task, uint32_t addr, uint32_t *dst)
{
	return copy_from_proc(task, addr, dst, sizeof(*dst));
}

static int arm_get_register(struct task *task, unsigned int reg, uint32_t *lp)
{
	if (ARRAY_SIZE(task->context.regs.uregs) >= reg) {
		long l;

		errno = 0;

		l = ptrace(PTRACE_PEEKUSER, task->pid, (void *)(reg * 4), 0);

		if (l == -1 && errno != 0)
			return -1;

		*lp = (uint32_t)l;
	}
	else
		*lp = fetch_reg(task, reg * 4);

	return 0;
}

static int arm_get_register_offpc(struct task *task, unsigned int reg, uint32_t *lp)
{
	if (arm_get_register(task, reg, lp) < 0)
		return -1;

	if (reg == ARM_REG_PC)
		*lp += 8;

	return 0;
}

static int arm_get_shifted_register(struct task *task, uint32_t inst, unsigned int carry, uint32_t pc, uint32_t *lp)
{
	unsigned int rm = BITS(inst, 0, 3);
	unsigned int shifttype = BITS(inst, 5, 6);
	uint32_t shift;
	uint32_t res;

	if (BIT(inst, 4)) {
		if (arm_get_register_offpc(task, BITS(inst, 8, 11), &shift) < 0)
			return -1;
		shift &= 0xff;
	} else
		shift = BITS(inst, 7, 11);

	if (rm == ARM_REG_PC)
		res = pc + (BIT(inst, 4) ? 12 : 8);
	else {
		if (arm_get_register(task, rm, &res) < 0)
			return -1;
	}

	switch(shifttype) {
	case 0:		/* LSL */
		res = shift >= 32 ? 0 : res << shift;
		break;
	case 1:		/* LSR */
		res = shift >= 32 ? 0 : res >> shift;
		break;
	case 2:		/* ASR */
		if (shift >= 32)
			shift = 31;
		res = ((res & 0x80000000L) ? ~((~res) >> shift) : res >> shift);
		break;
	case 3:		/* ROR/RRX */
		shift &= 31;
		if (shift == 0)
			res = (res >> 1) | (carry ? 0x80000000L : 0);
		else
			res = (res >> shift) | (res << (32 - shift));
		break;
	}

	*lp = res & 0xffffffff;
	return 0;
}

static uint32_t arm_branch_dest(uint32_t pc, const uint32_t insn)
{
	/* Bits 0-23 are signed immediate value.  */
	return pc + ((((insn & 0xffffff) ^ 0x800000) - 0x800000) << 2) + 8;
}

static int arm_get_next_pcs(struct task *task, const uint32_t pc, uint32_t next_pcs[2])
{
	uint32_t this_instr;
	uint32_t next;

	next_pcs[0] = 0;
	next_pcs[1] = 0;

	if (proc_read_32(task, pc, &this_instr) < 0)
		return -1;

	/* In theory, we sometimes don't even need to add any
	 * breakpoints at all.  If the conditional bits of the
	 * instruction indicate that it should not be taken, then we
	 * can just skip it altogether without bothering.  We could
	 * also emulate the instruction under the breakpoint.
	 *
	 * Here, we make it as simple as possible (though We Accept
	 * Patches).  */
	int nr = 0;

	/* ARM can branch either relatively by using a branch
	 * instruction, or absolutely, by doing arbitrary arithmetic
	 * with PC as the destination.  */
	const unsigned int cond = BITS(this_instr, 28, 31);
	const unsigned int opcode = BITS(this_instr, 24, 27);

	if (cond == COND_NV) {
		if (opcode == 0x0a || opcode == 0x0b) {
			uint32_t addr;

			/* Branch with Link and change to Thumb.  */
			addr = arm_branch_dest(pc, this_instr) | (((this_instr >> 24) & 0x1) << 1);
			next_pcs[nr++] = addr | 1;	/* thumb addr */
		}
	}
	else {
		uint32_t status;

		if (arm_get_register(task, ARM_REG_CPSR, &status) < 0)
			return -1;

		unsigned int c = status & FLAG_C ? 1 : 0;

		switch(opcode) {
		uint32_t operand1, operand2;

		case 0x0:
		case 0x1:			/* data processing */
		case 0x2:
		case 0x3:
			if (BITS(this_instr, 12, 15) != ARM_REG_PC)
				break;

			if (BITS(this_instr, 22, 25) == 0 && BITS(this_instr, 4, 7) == 9) /* multiply */
				goto invalid;

			/* BX <reg>, BLX <reg> */
			if (BITS(this_instr, 4, 27) == 0x12fff1 || BITS(this_instr, 4, 27) == 0x12fff3) {
				uint32_t tmp;

				if (arm_get_register_offpc(task, BITS(this_instr, 0, 3), &tmp) < 0)
					return -1;

				next_pcs[nr++] = tmp;
				return 0;
			}

			/* Multiply into PC.  */
			if (arm_get_register_offpc(task, BITS(this_instr, 16, 19), &operand1) < 0)
				return -1;

			if (BIT(this_instr, 25)) {
				uint32_t immval = BITS(this_instr, 0, 7);
				uint32_t rotate = 2 * BITS(this_instr, 8, 11);

				operand2 = ((immval >> rotate) | (immval << (32 - rotate))) & 0xffffffff;
			} else {
				/* operand 2 is a shifted register.  */
				if (arm_get_shifted_register(task, this_instr, c, pc, &operand2) < 0)
					return -1;
			}

			uint32_t result;

			switch(BITS(this_instr, 21, 24)) {
			case 0x0:	/*and */
				result = operand1 & operand2;
				break;
			case 0x1:	/*eor */
				result = operand1 ^ operand2;
				break;
			case 0x2:	/*sub */
				result = operand1 - operand2;
				break;
			case 0x3:	/*rsb */
				result = operand2 - operand1;
				break;
			case 0x4:	/*add */
				result = operand1 + operand2;
				break;
			case 0x5:	/*adc */
				result = operand1 + operand2 + c;
				break;
			case 0x6:	/*sbc */
				result = operand1 - operand2 + c;
				break;
			case 0x7:	/*rsc */
				result = operand2 - operand1 + c;
				break;
			case 0x8:
			case 0x9:
			case 0xa:
			case 0xb:	/* tst, teq, cmp, cmn */
				/* Only take the default branch.  */
				result = 0;
				break;
			case 0xc:	/*orr */
				result = operand1 | operand2;
				break;
			case 0xd:	/*mov */
				/* Always step into a function.  */
				result = operand2;
				break;
			case 0xe:	/*bic */
				result = operand1 & ~operand2;
				break;
			case 0xf:	/*mvn */
				result = ~operand2;
				break;
			default:
				result = 0;
				break;
			}

			next_pcs[nr++] = result;
			break;
		case 0x4:
		case 0x5:		/* data transfer */
		case 0x6:
		case 0x7:
			/* Ignore if insn isn't load or Rn not PC.  */
			if (!BIT(this_instr, 20) || BITS(this_instr, 12, 15) != ARM_REG_PC)
				break;

			if (BIT(this_instr, 22))
				goto invalid;

			/* byte write to PC */
			uint32_t base;
			if (arm_get_register_offpc(task, BITS(this_instr, 16, 19), &base) < 0)
				return -1;

			if (BIT(this_instr, 24)) {
				/* pre-indexed */
				uint32_t offset;

				if (BIT(this_instr, 25)) {
					if (arm_get_shifted_register(task, this_instr, c, pc, &offset) < 0)
						return -1;
				} else {
					offset = BITS(this_instr, 0, 11);
				}

				if (BIT(this_instr, 23))
					base += offset;
				else
					base -= offset;
			}

			if (proc_read_32(task, base, &next) < 0)
				return -1;

			next_pcs[nr++] = next;
			break;
		case 0x8:
		case 0x9:		/* block transfer */
			if (!BIT(this_instr, 20))
				break;

			/* LDM */
			if (BIT(this_instr, 15)) {
				/* Loading pc.  */
				uint32_t rn_val;
				int offset = 0;

				if (arm_get_register(task, BITS(this_instr, 16, 19), &rn_val) < 0)
					return -1;

				int pre = BIT(this_instr, 24);

				if (BIT(this_instr, 23)) {
					/* Bit U = up.  */
					offset = bitcount(BITS(this_instr, 0, 14)) * 4;
					if (pre)
						offset += 4;
				}
				else {
					if (pre)
						offset = -4;
				}

				if (proc_read_32(task, rn_val + offset, &next) < 0)
					return -1;

				next_pcs[nr++] = next;
			}
			break;
		case 0xb:		/* branch & link */
		case 0xa:		/* branch */
			next_pcs[nr++] = arm_branch_dest(pc, this_instr);
			break;
		case 0xc:
		case 0xd:
		case 0xe:		/* coproc ops */
		case 0xf:		/* SWI */
			break;
		}
	}
finish:
	/* Otherwise take the next instruction.  */
	if (!nr || cond != COND_ALWAYS)
		next_pcs[nr++] = pc + 4;
	return 0;

invalid:
	fprintf(stderr, "Invalid update to pc in instruction.\n");
	goto finish;
}

/* Return the size in bytes of the complete Thumb instruction whose
 * first halfword is INST1.  */
static int thumb_insn_size (unsigned short inst1)
{
	if ((inst1 & 0xe000) == 0xe000 && (inst1 & 0x1800) != 0)
		return 4;
	else
		return 2;
}

static int thumb_get_next_pcs(struct task *task, const uint32_t pc, uint32_t next_pcs[2])
{
	uint16_t inst1;
	uint32_t next;

	next_pcs[0] = 0;
	next_pcs[1] = 0;

	if (proc_read_16(task, pc, &inst1) < 0)
		return -1;

	int nr = 0;

	/* We currently ignore Thumb-2 conditional execution support
	 * (the IT instruction).  No branches are allowed in IT block,
	 * and it's not legal to jump in the middle of it, so unless
	 * we need to singlestep through large swaths of code, which
	 * we currently don't, we can ignore them.  */

	if ((inst1 & 0xff00) == 0xbd00)	{ /* pop {rlist, pc} */
		/* Fetch the saved PC from the stack.  It's stored above all of the other registers.  */
		uint32_t sp;

		if (arm_get_register(task, ARM_REG_SP, &sp) < 0 || proc_read_32(task, sp + bitcount(BITS(inst1, 0, 7)) * 4, &next) < 0)
			return -1;
		next_pcs[nr++] = next;
	}
	else
	if ((inst1 & 0xf000) == 0xd000) { /* conditional branch */
		const unsigned int cond = BITS(inst1, 8, 11);

		if (cond != 0x0f) { /* SWI */
			next_pcs[nr++] = pc + (SBITS(inst1, 0, 7) << 1);
			if (cond == COND_ALWAYS)
				return 0;
		}
	}
	else
	if ((inst1 & 0xf800) == 0xe000) { /* unconditional branch */
		next_pcs[nr++] = pc + (SBITS(inst1, 0, 10) << 1);
	}
	else
	if (thumb_insn_size(inst1) == 4) { /* 32-bit instruction */
		unsigned short inst2;

		if (proc_read_16(task, pc + 2, &inst2) < 0)
			return -1;

		if ((inst1 & 0xf800) == 0xf000 && (inst2 & 0x8000) == 0x8000) {
			/* Branches and miscellaneous control instructions.  */

			if ((inst2 & 0x1000) != 0 || (inst2 & 0xd001) == 0xc000) {
				/* B, BL, BLX.  */
				const int imm1 = SBITS(inst1, 0, 10);
				const unsigned int imm2 = BITS(inst2, 0, 10);
				const unsigned int j1 = BIT(inst2, 13);
				const unsigned int j2 = BIT(inst2, 11);

				int32_t offset = (imm1 << 12) + (imm2 << 1);

				offset ^= ((!j2) << 22) | ((!j1) << 23);

				next = pc + offset;

				/* For BLX make sure to clear the low bits.  */
				if (BIT(inst2, 12) == 0)
					next = next & 0xfffffffc;

				next_pcs[nr++] = next;
				return 0;
			}
			else
			if (inst1 == 0xf3de && (inst2 & 0xff00) == 0x3f00) {
				/* SUBS PC, LR, #imm8.  */
				if (arm_get_register(task, ARM_REG_LR, &next) < 0)
					return -1;

				next -= inst2 & 0x00ff;

				next_pcs[nr++] = next;
				return 0;
			}
			else
			if ((inst2 & 0xd000) == 0x8000 && (inst1 & 0x0380) != 0x0380) {
				/* Conditional branch.  */
				const int sign = SBITS(inst1, 10, 10);
				const unsigned int imm1 = BITS(inst1, 0, 5);
				const unsigned int imm2 = BITS(inst2, 0, 10);
				const unsigned int j1 = BIT(inst2, 13);
				const unsigned int j2 = BIT(inst2, 11);

				int32_t offset = (sign << 20) + (j2 << 19) + (j1 << 18);

				offset += (imm1 << 12) + (imm2 << 1);

				next_pcs[nr++] = pc + offset;

				if (BITS(inst1, 6, 9) == COND_ALWAYS)
					return 0;
			}
		}
		else
		if ((inst1 & 0xfe50) == 0xe810) {
			int load_pc = 1;
			int offset;

			if (BIT(inst1, 7) && !BIT(inst1, 8)) {
				/* LDMIA or POP */
				if (!BIT(inst2, 15))
					load_pc = 0;
				offset = bitcount(inst2) * 4 - 4;
			}
			else
			if (!BIT(inst1, 7) && BIT(inst1, 8)) {
				/* LDMDB */
				if (!BIT(inst2, 15))
					load_pc = 0;
				offset = -4;
			}
			else
			if (BIT(inst1, 7) && BIT(inst1, 8)) {
				/* RFEIA */
				offset = 0;
			}
			else
			if (!BIT(inst1, 7) && !BIT(inst1, 8)) {
				/* RFEDB */
				offset = -8;
			} else {
				load_pc = 0;
			}

			if (load_pc) {
				uint32_t addr;

				if (arm_get_register(task, BITS(inst1, 0, 3), &addr) < 0)
					return -1;

				addr = addr + offset;

				if (proc_read_32(task, addr, &next) < 0)
					return -1;

				next_pcs[nr++] = next;
			}
		}
		else
		if ((inst1 & 0xffef) == 0xea4f && (inst2 & 0xfff0) == 0x0f00) {
			/* MOV PC or MOVS PC.  */
			if (arm_get_register(task, BITS(inst2, 0, 3), &next) < 0)
				return -1;

			next_pcs[nr++] = next;
		}
		else
		if ((inst1 & 0xff70) == 0xf850 && (inst2 & 0xf000) == 0xf000) {
			/* LDR PC.  */
			const unsigned int rn = BITS(inst1, 0, 3);
			uint32_t base;

			if (arm_get_register(task, rn, &base) < 0)
				return -1;

			int load_pc = 1;

			if (rn == ARM_REG_PC) {
				base = (base + 4) & ~0x3;
				if (BIT(inst1, 7))
					base += BITS(inst2, 0, 11);
				else
					base -= BITS(inst2, 0, 11);
			}
			else
			if (BIT(inst1, 7)) {
				base += BITS(inst2, 0, 11);
			}
			else
			if (BIT(inst2, 11)) {
				if (BIT(inst2, 10)) {
					if (BIT(inst2, 9))
						base += BITS(inst2, 0, 7);
					else
						base -= BITS(inst2, 0, 7);
				}
			}
			else
			if ((inst2 & 0x0fc0) == 0x0000) {
				uint32_t v;

				if (arm_get_register(task, BITS(inst2, 0, 3), &v) < 0)
					return -1;
				base += v << BITS(inst2, 4, 5);
			} else {
				/* Reserved.  */
				load_pc = 0;
			}

			if (load_pc) {
				if (proc_read_32(task, base, &next) < 0)
					return -1;

				next_pcs[nr++] = next;
			}
		}
		else
		if ((inst1 & 0xfff0) == 0xe8d0 && (inst2 & 0xfff0) == 0xf000) {
			/* TBB.  */
			uint32_t table;
			uint32_t offset;
			uint8_t length;
			const unsigned int tbl_reg = BITS(inst1, 0, 3);

			if (tbl_reg == ARM_REG_PC)
				/* Regcache copy of PC isn't right yet.  */
				table = pc + 4;
			else {
				if (arm_get_register(task, tbl_reg, &table) < 0)
					return -1;
			}

			if (arm_get_register(task, BITS(inst2, 0, 3), &offset) < 0)
				return -1;

			table += offset;

			if (proc_read_8(task, table, &length) < 0)
				return -1;

			next_pcs[nr++] = pc + 2 * length;

		}
		else
		if ((inst1 & 0xfff0) == 0xe8d0 && (inst2 & 0xfff0) == 0xf010) {
			/* TBH.  */
			uint32_t table;
			uint32_t offset;
			uint16_t length;

			const unsigned int tbl_reg = BITS(inst1, 0, 3);

			if (tbl_reg == ARM_REG_PC)
				/* Regcache copy of PC isn't right yet.  */
				table = pc + 4;
			else {
				if (arm_get_register(task, tbl_reg, &table) < 0)
					return -1;
			}

			if (arm_get_register(task, BITS(inst2, 0, 3), &offset) < 0)
				return -1;

			table += 2 * offset;
			if (proc_read_16(task, table, &length) < 0)
				return -1;

			next_pcs[nr++] = pc + 2 * length;
		}
	}


	/* Otherwise take the next instruction.  */
	if (!nr)
		next_pcs[nr++] = pc + thumb_insn_size(inst1);
	return 0;
}

static int ptrace_cont(struct task *task)
{
	if (ptrace(PTRACE_CONT, task->pid, 0, 0) == -1) {
		if (errno != ESRCH)
			fprintf(stderr, "%s PTRACE_CONT pid=%d %s\n", __FUNCTION__, task->pid, strerror(errno));
		return -1;
	}
	return 0;
}

int do_singlestep(struct task *task, struct breakpoint *bp)
{
	const uint32_t pc = get_instruction_pointer(task);
	uint32_t cpsr;
	struct breakpoint *bp1, *bp2;
	int ret;
	uint32_t next_pcs[2];

	if (arm_get_register(task, ARM_REG_CPSR, &cpsr) < 0)
		return -1;

	if (BIT(cpsr, 5))
		ret = thumb_get_next_pcs(task, pc, next_pcs);
	else
		ret = arm_get_next_pcs(task, pc, next_pcs);

	if (ret < 0)
		return -1;

	bp1 = breakpoint_find(task, next_pcs[0]);
	if (!bp1) {
		bp1 = breakpoint_new(task, next_pcs[0], NULL, SW_BP);
		if (!bp1)
			return -1;
	}
	if (!bp1->enabled)
		breakpoint_enable(task, bp1);
	else
		bp1 = NULL;

	if (next_pcs[1]) {
		bp2 = breakpoint_find(task, next_pcs[1]);
		if (!bp2) {
			bp2 = breakpoint_new(task, next_pcs[1], NULL, SW_BP);
			if (!bp2)
				return -1;
		}
		if (!bp2->enabled)
			breakpoint_enable(task, bp2);
		else
			bp2 = NULL;
	}
	else
		bp2 = NULL;

	ret = handle_singlestep(task, ptrace_cont, bp);

	if (bp1)
		breakpoint_disable(task, bp1);
	if (bp2)
		breakpoint_disable(task, bp2);

	return ret;
}

