/*
 * This file is part of mtrace.
 * Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
 *  This file is based on the libunwind source
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

#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <assert.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <limits.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>

#include "backend.h"
#include "common.h"
#include "debug.h"
#include "dwarf.h"
#include "library.h"
#include "task.h"

#define MAX_EXPR_STACK_SIZE	64

#define NUM_OPERANDS(signature)	(((signature) >> 6) & 0x3)
#define OPND1_TYPE(signature)	(((signature) >> 3) & 0x7)
#define OPND2_TYPE(signature)	(((signature) >> 0) & 0x7)

#define OPND_SIGNATURE(n, t1, t2)	(((n) << 6) | ((t1) << 3) | ((t2) << 0))
#define OPND1(t1)			OPND_SIGNATURE(1, t1, 0)
#define OPND2(t1, t2)			OPND_SIGNATURE(2, t1, t2)

#define VAL8	0x0
#define VAL16	0x1
#define VAL32	0x2
#define VAL64	0x3
#define ULEB128	0x4
#define SLEB128	0x5
#define OFFSET	0x6		/* 32-bit offset for 32-bit DWARF, 64-bit otherwise */
#define ADDR	0x7		/* Machine address.  */

#define DWARF_CIE_VERSION	3
#define DWARF_CIE_VERSION_GCC	1	/* GCC emits version 1??? */
#define DWARF_CFA_OPCODE_MASK	0xc0
#define DWARF_CFA_OPERAND_MASK	0x3f

#define DW_EH_VERSION	1	/* The version we're implementing */

/* For uniformity, we'd like to treat the CFA save-location like any
   other register save-location, but this doesn't quite work, because
   the CFA can be expressed as a (REGISTER,OFFSET) pair.  To handle
   this, we use two dwarf_save_loc structures to describe the CFA.
   The first one (CFA_REG_COLUMN), tells us where the CFA is saved.
   In the case of DWARF_WHERE_EXPR, the CFA is defined by a DWARF
   location expression whose address is given by member "val".  In the
   case of DWARF_WHERE_REG, member "val" gives the number of the
   base-register and the "val" member of DWARF_CFA_OFF_COLUMN gives
   the offset value.  */
#define DWARF_CFA_REG_COLUMN(as)	((as)->num_regs + 0)
#define DWARF_CFA_OFF_COLUMN(as)	((as)->num_regs + 1)

/* DWARF Pointer-Encoding (PEs).

   Pointer-Encodings were invented for the GCC exception-handling
   support for C++, but they represent a rather generic way of
   describing the format in which an address/pointer is stored and
   hence we include the definitions here, in the main dwarf.h file.
   The Pointer-Encoding format is partially documented in Linux Base
   Spec v1.3 (http://www.linuxbase.org/spec/).  The rest is reverse
   engineered from GCC.
*/
#define DW_EH_PE_FORMAT_MASK	0x0f	/* format of the encoded value */
#define DW_EH_PE_APPL_MASK	0x70	/* how the value is to be applied */
/* Flag bit.  If set, the resulting pointer is the address of the word
   that contains the final address.  */
#define DW_EH_PE_indirect	0x80

/* Pointer-encoding formats: */
#define DW_EH_PE_omit		0xff
#define DW_EH_PE_ptr		0x00	/* pointer-sized unsigned value */
#define DW_EH_PE_uleb128	0x01	/* unsigned LE base-128 value */
#define DW_EH_PE_udata2		0x02	/* unsigned 16-bit value */
#define DW_EH_PE_udata4		0x03	/* unsigned 32-bit value */
#define DW_EH_PE_udata8		0x04	/* unsigned 64-bit value */
#define DW_EH_PE_sleb128	0x09	/* signed LE base-128 value */
#define DW_EH_PE_sdata2		0x0a	/* signed 16-bit value */
#define DW_EH_PE_sdata4		0x0b	/* signed 32-bit value */
#define DW_EH_PE_sdata8		0x0c	/* signed 64-bit value */

/* Pointer-encoding application: */
#define DW_EH_PE_absptr		0x00	/* absolute value */
#define DW_EH_PE_pcrel		0x10	/* rel. to addr. of encoded value */
#define DW_EH_PE_textrel	0x20	/* text-relative (GCC-specific???) */
#define DW_EH_PE_datarel	0x30	/* data-relative */
/* The following are not documented by LSB v1.3, yet they are used by
   GCC, presumably they aren't documented by LSB since they aren't
   used on Linux:  */
#define DW_EH_PE_funcrel	0x40	/* start-of-procedure-relative */
#define DW_EH_PE_aligned	0x50	/* aligned pointer */

struct table_entry {
	int32_t start_ip_offset;
	int32_t fde_offset;
};

enum dwarf_where {
	DWARF_WHERE_UNDEF,	/* register isn't saved at all */
	DWARF_WHERE_SAME,	/* register has same value as in prev. frame */
	DWARF_WHERE_CFAREL,	/* register saved at CFA-relative address */
	DWARF_WHERE_REG,	/* register saved in another register */
	DWARF_WHERE_EXPR,	/* register saved */
	DWARF_WHERE_VAL_EXPR,	/* register has computed value */
};

enum dwarf_cfa {
	DW_CFA_advance_loc = 0x40,
	DW_CFA_offset = 0x80,
	DW_CFA_restore = 0xc0,
	DW_CFA_nop = 0x00,
	DW_CFA_set_loc = 0x01,
	DW_CFA_advance_loc1 = 0x02,
	DW_CFA_advance_loc2 = 0x03,
	DW_CFA_advance_loc4 = 0x04,
	DW_CFA_offset_extended = 0x05,
	DW_CFA_restore_extended = 0x06,
	DW_CFA_undefined = 0x07,
	DW_CFA_same_value = 0x08,
	DW_CFA_register = 0x09,
	DW_CFA_remember_state = 0x0a,
	DW_CFA_restore_state = 0x0b,
	DW_CFA_def_cfa = 0x0c,
	DW_CFA_def_cfa_register = 0x0d,
	DW_CFA_def_cfa_offset = 0x0e,
	DW_CFA_def_cfa_expression = 0x0f,
	DW_CFA_expression = 0x10,
	DW_CFA_offset_extended_sf = 0x11,
	DW_CFA_def_cfa_sf = 0x12,
	DW_CFA_def_cfa_offset_sf = 0x13,
	DW_CFA_val_expression = 0x16,
	DW_CFA_lo_user = 0x1c,
	DW_CFA_MIPS_advance_loc8 = 0x1d,
	DW_CFA_GNU_window_save = 0x2d,
	DW_CFA_GNU_args_size = 0x2e,
	DW_CFA_GNU_negative_offset_extended = 0x2f,
	DW_CFA_hi_user = 0x3c
};

enum dwarf_expr_op {
	DW_OP_addr = 0x03,
	DW_OP_deref = 0x06,
	DW_OP_const1u = 0x08,
	DW_OP_const1s = 0x09,
	DW_OP_const2u = 0x0a,
	DW_OP_const2s = 0x0b,
	DW_OP_const4u = 0x0c,
	DW_OP_const4s = 0x0d,
	DW_OP_const8u = 0x0e,
	DW_OP_const8s = 0x0f,
	DW_OP_constu = 0x10,
	DW_OP_consts = 0x11,
	DW_OP_dup = 0x12,
	DW_OP_drop = 0x13,
	DW_OP_over = 0x14,
	DW_OP_pick = 0x15,
	DW_OP_swap = 0x16,
	DW_OP_rot = 0x17,
	DW_OP_xderef = 0x18,
	DW_OP_abs = 0x19,
	DW_OP_and = 0x1a,
	DW_OP_div = 0x1b,
	DW_OP_minus = 0x1c,
	DW_OP_mod = 0x1d,
	DW_OP_mul = 0x1e,
	DW_OP_neg = 0x1f,
	DW_OP_not = 0x20,
	DW_OP_or = 0x21,
	DW_OP_plus = 0x22,
	DW_OP_plus_uconst = 0x23,
	DW_OP_shl = 0x24,
	DW_OP_shr = 0x25,
	DW_OP_shra = 0x26,
	DW_OP_xor = 0x27,
	DW_OP_skip = 0x2f,
	DW_OP_bra = 0x28,
	DW_OP_eq = 0x29,
	DW_OP_ge = 0x2a,
	DW_OP_gt = 0x2b,
	DW_OP_le = 0x2c,
	DW_OP_lt = 0x2d,
	DW_OP_ne = 0x2e,
	DW_OP_lit0 = 0x30,
	DW_OP_lit31 = 0x4f,
	DW_OP_reg0 = 0x50,
	DW_OP_reg31 = 0x6f,
	DW_OP_breg0 = 0x70,
	DW_OP_breg31 = 0x8f,
	DW_OP_regx = 0x90,
	DW_OP_fbreg = 0x91,
	DW_OP_bregx = 0x92,
	DW_OP_piece = 0x93,
	DW_OP_deref_size = 0x94,
	DW_OP_xderef_size = 0x95,
	DW_OP_nop = 0x96,
	DW_OP_push_object_address = 0x97,
	DW_OP_call2 = 0x98,
	DW_OP_call4 = 0x99,
	DW_OP_call_ref = 0x9a,
	DW_OP_lo_user = 0xe0,
	DW_OP_hi_user = 0xff
};

struct dwarf_eh_frame_hdr {
	unsigned char version;
	unsigned char eh_frame_ptr_enc;
	unsigned char fde_count_enc;
	unsigned char table_enc;
	/* The rest of the header is variable-length and consists of the
	   following members:

	   encoded_t eh_frame_ptr;
	   encoded_t fde_count;
	   struct
	   {
	   encoded_t start_ip; // first address covered by this FDE
	   encoded_t fde_addr; // address of the FDE
	   }
	   binary_search_table[fde_count];  */
};

struct dwarf_reg {
	enum dwarf_where where;	/* how is the register saved? */
	arch_addr_t val;	/* where it's saved */
};

struct dwarf_reg_state {
	struct dwarf_reg reg[2];/* the registers are dynamically allocated */
};

static const uint8_t dwarf_operands[256] = {
	[DW_OP_addr] = OPND1(ADDR),
	[DW_OP_const1u] = OPND1(VAL8),
	[DW_OP_const1s] = OPND1(VAL8),
	[DW_OP_const2u] = OPND1(VAL16),
	[DW_OP_const2s] = OPND1(VAL16),
	[DW_OP_const4u] = OPND1(VAL32),
	[DW_OP_const4s] = OPND1(VAL32),
	[DW_OP_const8u] = OPND1(VAL64),
	[DW_OP_const8s] = OPND1(VAL64),
	[DW_OP_pick] = OPND1(VAL8),
	[DW_OP_plus_uconst] = OPND1(ULEB128),
	[DW_OP_skip] = OPND1(VAL16),
	[DW_OP_bra] = OPND1(VAL16),
	[DW_OP_breg0 + 0] = OPND1(SLEB128),
	[DW_OP_breg0 + 1] = OPND1(SLEB128),
	[DW_OP_breg0 + 2] = OPND1(SLEB128),
	[DW_OP_breg0 + 3] = OPND1(SLEB128),
	[DW_OP_breg0 + 4] = OPND1(SLEB128),
	[DW_OP_breg0 + 5] = OPND1(SLEB128),
	[DW_OP_breg0 + 6] = OPND1(SLEB128),
	[DW_OP_breg0 + 7] = OPND1(SLEB128),
	[DW_OP_breg0 + 8] = OPND1(SLEB128),
	[DW_OP_breg0 + 9] = OPND1(SLEB128),
	[DW_OP_breg0 + 10] = OPND1(SLEB128),
	[DW_OP_breg0 + 11] = OPND1(SLEB128),
	[DW_OP_breg0 + 12] = OPND1(SLEB128),
	[DW_OP_breg0 + 13] = OPND1(SLEB128),
	[DW_OP_breg0 + 14] = OPND1(SLEB128),
	[DW_OP_breg0 + 15] = OPND1(SLEB128),
	[DW_OP_breg0 + 16] = OPND1(SLEB128),
	[DW_OP_breg0 + 17] = OPND1(SLEB128),
	[DW_OP_breg0 + 18] = OPND1(SLEB128),
	[DW_OP_breg0 + 19] = OPND1(SLEB128),
	[DW_OP_breg0 + 20] = OPND1(SLEB128),
	[DW_OP_breg0 + 21] = OPND1(SLEB128),
	[DW_OP_breg0 + 22] = OPND1(SLEB128),
	[DW_OP_breg0 + 23] = OPND1(SLEB128),
	[DW_OP_breg0 + 24] = OPND1(SLEB128),
	[DW_OP_breg0 + 25] = OPND1(SLEB128),
	[DW_OP_breg0 + 26] = OPND1(SLEB128),
	[DW_OP_breg0 + 27] = OPND1(SLEB128),
	[DW_OP_breg0 + 28] = OPND1(SLEB128),
	[DW_OP_breg0 + 29] = OPND1(SLEB128),
	[DW_OP_breg0 + 30] = OPND1(SLEB128),
	[DW_OP_breg0 + 31] = OPND1(SLEB128),
	[DW_OP_regx] = OPND1(ULEB128),
	[DW_OP_fbreg] = OPND1(SLEB128),
	[DW_OP_bregx] = OPND2(ULEB128, SLEB128),
	[DW_OP_piece] = OPND1(ULEB128),
	[DW_OP_deref_size] = OPND1(VAL8),
	[DW_OP_xderef_size] = OPND1(VAL8),
	[DW_OP_call2] = OPND1(VAL16),
	[DW_OP_call4] = OPND1(VAL32),
	[DW_OP_call_ref] = OPND1(OFFSET)
};

static int dwarf_access_mem(struct dwarf_addr_space *as, arch_addr_t addr, void *valp, size_t size)
{
	if (!addr) {
		debug(DEBUG_DWARF, "invalid null memory access");
		return -DWARF_EINVAL;
	}

	if (!valp)
		return 0;

	if (!as) {
		memcpy(valp, (void *)addr, size);
		return 0;
	}

	if (as->addr && as->addr <= addr && addr + size - as->addr <= sizeof(as->val)) {
		memcpy(valp, &as->val_bytes[addr - as->addr], size);
		return 0;
	}

	if (copy_from_proc(as->task, addr, &as->val, sizeof(as->val)) != sizeof(as->val)) {
		debug(DEBUG_DWARF, "cannot access memory %#lx of pid %d", addr, as->task->pid);
		return -DWARF_EINVAL;
	}

	as->addr = addr;
	memcpy(valp, as->val_bytes, size);

	return 0;
}

static inline int dwarf_read8(struct dwarf_addr_space *as, arch_addr_t *addr, void *valp)
{
	int ret;

	ret = dwarf_access_mem(as, *addr, valp, 1);
	if (ret)
		return ret;

	*addr += 1;
	return 0;
}

static inline int dwarf_read16(struct dwarf_addr_space *as, arch_addr_t *addr, void *valp)
{
	int ret;

	ret = dwarf_access_mem(as, *addr, valp, 2);
	if (ret)
		return ret;

	*addr += 2;
	return 0;
}

static inline int dwarf_read32(struct dwarf_addr_space *as, arch_addr_t *addr, void *valp)
{
	int ret;

	ret = dwarf_access_mem(as, *addr, valp, 4);
	if (ret)
		return ret;

	*addr += 4;
	return 0;
}

static inline int dwarf_read64(struct dwarf_addr_space *as, arch_addr_t *addr, void *valp)
{
	int ret;

	ret = dwarf_access_mem(as, *addr, valp, 8);
	if (ret)
		return ret;

	*addr += 8;
	return 0;
}

static inline int dwarf_readw(struct dwarf_addr_space *as, arch_addr_t *addr, arch_addr_t *valp, int is_64bit)
{
	int ret;

	if (is_64bit) {
		uint64_t u64;

		ret = dwarf_read64(as, addr, &u64);

		if (valp)
			*valp = u64;
	}
	else {
		uint32_t u32;

		ret = dwarf_read32(as, addr, &u32);

		if (valp)
			*valp = u32;
	}
	return ret;
}

static int dwarf_read_uleb128(struct dwarf_addr_space *as, arch_addr_t *addr, arch_addr_t *valp)
{
	arch_addr_t val = 0, shift = 0;
	unsigned char byte;
	int ret;

	do {
		if ((ret = dwarf_read8(as, addr, &byte)) < 0)
			return ret;

		val |= ((arch_addr_t) byte & 0x7f) << shift;
		shift += 7;
	}
	while (byte & 0x80);

	if (valp)
		*valp = val;
	return 0;
}

static int dwarf_read_sleb128(struct dwarf_addr_space *as, arch_addr_t *addr, arch_addr_t *valp)
{
	arch_addr_t val = 0, shift = 0;
	unsigned char byte;
	int ret;

	do {
		if ((ret = dwarf_read8(as, addr, &byte)) < 0)
			return ret;

		val |= ((arch_addr_t) byte & 0x7f) << shift;
		shift += 7;
	}
	while (byte & 0x80);

	if (shift < 8 *sizeof(arch_addr_t) && (byte & 0x40) != 0)
		/* sign-extend negative value */
		val |= ((arch_addr_t) -1) << shift;

	if (valp)
		*valp = val;
	return 0;
}

static int dwarf_read_encoded_pointer(struct dwarf_addr_space *as, int local,
		arch_addr_t *addr, unsigned char encoding, arch_addr_t *valp, arch_addr_t start_ip)
{
	struct dwarf_addr_space *indirect_as = as;
	arch_addr_t val, initial_addr = *addr;
	arch_addr_t gp = as->cursor.lib->gp;
	int is_64bit = as->task->is_64bit;
	void *tmp_ptr;
	int ret;
	union {
		uint16_t uval16;
		uint32_t uval32;
		uint64_t uval64;
		int16_t sval16;
		int32_t sval32;
		int64_t sval64;
		arch_addr_t addr;
	} tmp;

#ifdef DEBUG
	struct dwarf_cursor *c = &as->cursor;
	struct library *lib = c->lib;

	if (*addr < ARCH_ADDR_T(lib->image_addr))
		fatal("invalid access mem: addr %#lx < %p", *addr, lib->image_addr);
	if (*addr >= ARCH_ADDR_T(lib->image_addr + lib->load_size))
		fatal("invalid access mem: addr %#lx >= %p", *addr, lib->image_addr + lib->load_size);
#endif

	memset(&tmp, 0, sizeof(tmp));

	if (valp)
		tmp_ptr = &tmp;
	else {
		valp = &val;
		tmp_ptr = NULL;
	}
	
	if (local)
		as = NULL;

	/* DW_EH_PE_omit and DW_EH_PE_aligned don't follow the normal
	   format/application encoding.  Handle them first.  */
	if (encoding == DW_EH_PE_omit) {
		*valp = 0;
		return 0;
	}
	else
	if (encoding == DW_EH_PE_aligned) {
		int size = is_64bit ? sizeof(uint64_t) : sizeof(uint32_t);

		*addr = (initial_addr + size - 1) & -size;

		if ((ret = dwarf_readw(as, addr, tmp_ptr, is_64bit)) < 0)
			return ret;
		*valp = tmp.addr;
		return 0;
	}

	switch (encoding & DW_EH_PE_FORMAT_MASK) {
	case DW_EH_PE_ptr:
		if ((ret = dwarf_readw(as, addr, tmp_ptr, is_64bit)) < 0)
			return ret;
		val = tmp.addr;
		break;
	case DW_EH_PE_uleb128:
		if ((ret = dwarf_read_uleb128(as, addr, &val)) < 0)
			return ret;
		break;
	case DW_EH_PE_udata2:
		if ((ret = dwarf_read16(as, addr, tmp_ptr)) < 0)
			return ret;
		val = tmp.uval16;
		break;
	case DW_EH_PE_udata4:
		if ((ret = dwarf_read32(as, addr, tmp_ptr)) < 0)
			return ret;
		val = tmp.uval32;
		break;
	case DW_EH_PE_udata8:
		if ((ret = dwarf_read64(as, addr, tmp_ptr)) < 0)
			return ret;
		val = tmp.uval64;
		break;
	case DW_EH_PE_sleb128:
		if ((ret = dwarf_read_sleb128(as, addr, &val)) < 0)
			return ret;
		break;
	case DW_EH_PE_sdata2:
		if ((ret = dwarf_read16(as, addr, tmp_ptr)) < 0)
			return ret;
		val = tmp.sval16;
		break;
	case DW_EH_PE_sdata4:
		if ((ret = dwarf_read32(as, addr, tmp_ptr)) < 0)
			return ret;
		val = tmp.sval32;
		break;
	case DW_EH_PE_sdata8:
		if ((ret = dwarf_read64(as, addr, tmp_ptr)) < 0)
			return ret;
		val = tmp.sval64;
		break;
	default:
		debug(DEBUG_DWARF, "unexpected encoding format 0x%x", encoding & DW_EH_PE_FORMAT_MASK);
		return -DWARF_EINVAL;
	}

	if (!val) {
		/* 0 is a special value and always absolute.  */
		*valp = 0;
		return 0;
	}

	switch (encoding & DW_EH_PE_APPL_MASK) {
	case DW_EH_PE_absptr:
		break;
	case DW_EH_PE_pcrel:
		val += initial_addr;
		break;
	case DW_EH_PE_datarel:
		/* XXX For now, assume that data-relative addresses are relative to the global pointer. */
		val += gp;
		break;
	case DW_EH_PE_funcrel:
		val += start_ip;
		break;
	case DW_EH_PE_textrel:
		/* XXX For now we don't support text-rel values. */
	default:
		debug(DEBUG_DWARF, "unexpected application type 0x%x", encoding & DW_EH_PE_APPL_MASK);
		return -DWARF_EINVAL;
	}

	/* Trim off any extra bits.  Assume that sign extension isn't
	   required; the only place it is needed is MIPS kernel space
	   addresses.  */
	if (!is_64bit) 
		val = (uint32_t)val;

	if (encoding & DW_EH_PE_indirect) {
		if (indirect_as) {
			arch_addr_t indirect_addr = val;

			if (tmp_ptr) {
				if ((ret = dwarf_readw(indirect_as, &indirect_addr, &val, is_64bit)) < 0)
					return ret;
			}
			else
				val = 0;
		}
		else {
			debug(DEBUG_DWARF, "unexpected indirect addressing %#lx", val);
			return -DWARF_EINVAL;
		}
	}

	*valp = val;
	return 0;
}

static inline int dwarf_read_encoded_pointer_local(struct dwarf_addr_space *as, arch_addr_t *addr, unsigned char encoding, arch_addr_t *valp, arch_addr_t start_ip)
{
	return dwarf_read_encoded_pointer(as, 1, addr, encoding, valp, start_ip);
}

static int parse_cie(struct dwarf_addr_space *as, arch_addr_t addr, struct dwarf_cie_info *dci)
{
	uint8_t version, ch, augstr[5], fde_encoding;
	arch_addr_t len, cie_end_addr, aug_size;
	uint32_t u32val;
	uint64_t u64val;
	size_t i;
	int ret;

	/* Pick appropriate default for FDE-encoding.  DWARF spec says
	   start-IP (initial_location) and the code-size (address_range) are
	   "address-unit sized constants".  The `R' augmentation can be used
	   to override this, but by default, we pick an address-sized unit
	   for fde_encoding.  */
	if (as->task->is_64bit)
		fde_encoding = DW_EH_PE_udata8;
	else
		fde_encoding = DW_EH_PE_udata4;

	dci->lsda_encoding = DW_EH_PE_omit;

	if ((ret = dwarf_read32(NULL, &addr, &u32val)) < 0)
		return ret;

	if (u32val != 0xffffffff) {
		/* the CIE is in the 32-bit DWARF format */
		uint32_t cie_id;

		len = u32val;
		cie_end_addr = addr + len;

		if ((ret = dwarf_read32(NULL, &addr, &cie_id)) < 0)
			return ret;

		if (cie_id) {
			debug(DEBUG_DWARF, "Unexpected CIE id %x", cie_id);
			return -DWARF_EINVAL;
		}
	}
	else {
		/* the CIE is in the 64-bit DWARF format */
		uint64_t cie_id;

		if ((ret = dwarf_read64(NULL, &addr, &u64val)) < 0)
			return ret;

		len = u64val;
		cie_end_addr = addr + len;

		if ((ret = dwarf_read64(NULL, &addr, &cie_id)) < 0)
			return ret;

		if (cie_id) {
			debug(DEBUG_DWARF, "Unexpected CIE id %llx", (long long)cie_id);
			return -DWARF_EINVAL;
		}
	}
	dci->cie_instr_end = cie_end_addr;

	if ((ret = dwarf_read8(NULL, &addr, &version)) < 0)
		return ret;

	if (version != DWARF_CIE_VERSION && version != DWARF_CIE_VERSION_GCC) {
		debug(DEBUG_DWARF, "Got CIE version %u, expected version " STR(DWARF_CIE_VERSION) "or" STR(DWARF_CIE_VERSION_GCC), version);
		return -DWARF_EBADVERSION;
	}

	/* read and parse the augmentation string: */
	memset(augstr, 0, sizeof(augstr));
	for (i = 0;;) {
		if ((ret = dwarf_read8(NULL, &addr, &ch)) < 0)
			return ret;

		if (!ch)
			break;	/* end of augmentation string */

		if (i < sizeof(augstr) - 1)
			augstr[i++] = ch;
	}

	if ((ret = dwarf_read_uleb128(NULL, &addr, &dci->code_align)) < 0 || (ret = dwarf_read_sleb128(NULL, &addr, &dci->data_align)) < 0)
		return ret;

	/* Read the return-address column either as a u8 or as a uleb128.  */
	if (version == 1) {
		if ((ret = dwarf_read8(NULL, &addr, &ch)) < 0)
			return ret;
		dci->ret_addr_column = dwarf_to_regnum(ch);
	}
	else {
		arch_addr_t val;

		if ((ret = dwarf_read_uleb128(NULL, &addr, &val)) < 0)
			return ret;
		dci->ret_addr_column = dwarf_to_regnum(val);
	}

	i = 0;
	if (augstr[0] == 'z') {
		dci->sized_augmentation = 1;
		if ((ret = dwarf_read_uleb128(NULL, &addr, &aug_size)) < 0)
			return ret;
		i++;
	}

	for (; i < sizeof(augstr) && augstr[i]; ++i) {
		switch (augstr[i]) {
		case 'L':
			/* read the LSDA pointer-encoding format.  */
			if ((ret = dwarf_read8(NULL, &addr, &ch)) < 0)
				return ret;
			dci->lsda_encoding = ch;
			break;
		case 'R':
			/* read the FDE pointer-encoding format.  */
			if ((ret = dwarf_read8(NULL, &addr, &fde_encoding)) < 0)
				return ret;
			break;
		case 'P':
		 {
			uint8_t	handler_encoding;

			/* read the personality-routine pointer-encoding format.  */
			if ((ret = dwarf_read8(NULL, &addr, &handler_encoding)) < 0)
				return ret;
			if ((ret = dwarf_read_encoded_pointer_local(as, &addr, handler_encoding, NULL, 0)) < 0)
				break;
		 }
		case 'S':
			/* This is a signal frame. */
			dci->signal_frame = 1;

			/* Temporarily set it to one so dwarf_parse_fde() knows that
			   it should fetch the actual ABI/TAG pair from the FDE.  */
			dci->have_abi_marker = 1;
			break;
		default:
			debug(DEBUG_DWARF, "Unexpected augmentation string `%s'", augstr);
			if (dci->sized_augmentation)
				/* If we have the size of the augmentation body, we can skip
				   over the parts that we don't understand, so we're OK. */
				goto done;
			else
				return -DWARF_EINVAL;
		}
	}
done:
	dci->fde_encoding = fde_encoding;
	dci->cie_instr_start = addr;
	return 0;
}

static int dwarf_extract_cfi_from_fde(struct dwarf_addr_space *as, void *addrp)
{
	int ret;
	uint32_t u32val;
	arch_addr_t fde_end_addr, cie_addr, cie_offset_addr, cie_offset;
	struct dwarf_cie_info *dci = &as->cursor.dci;
	arch_addr_t addr = (arch_addr_t)addrp;

	if ((ret = dwarf_read32(NULL, &addr, &u32val)) < 0)
		return ret;

	if (u32val != 0xffffffff) {
		int32_t cie_offset32;

		/* In some configurations, an FDE with a 0 length indicates the
		   end of the FDE-table.  */
		if (!u32val) {
			debug(DEBUG_DWARF, "zero FDE");
			return -DWARF_ENOINFO;
		}

		/* the FDE is in the 32-bit DWARF format */

		fde_end_addr = addr + u32val;
		cie_offset_addr = addr;

		if ((ret = dwarf_read32(NULL, &addr, &cie_offset32)) < 0)
			return ret;

		cie_offset = cie_offset32;
	} else {
		int64_t cie_offset64;
		uint64_t u64val;

		/* the FDE is in the 64-bit DWARF format */

		if ((ret = dwarf_read64(NULL, &addr, &u64val)) < 0)
			return ret;

		fde_end_addr = addr + u64val;
		cie_offset_addr = addr;

		if ((ret = dwarf_read64(NULL, &addr, &cie_offset64)) < 0)
			return ret;

		cie_offset = cie_offset64;
	}

	memset(dci, 0, sizeof(*dci));

	/* ignore CIEs (happens during linear searches) */
	if (!cie_offset)
		return 0;

	/* DWARF says that the CIE_pointer in the FDE is a
	   .debug_frame-relative offset, but the GCC-generated .eh_frame
	   sections instead store a "pcrelative" offset, which is just
	   as fine as it's self-contained.  */
	cie_addr = cie_offset_addr - cie_offset;

	if ((ret = parse_cie(as, cie_addr, dci)) < 0)
		return ret;

	if ((ret = dwarf_read_encoded_pointer_local(as, &addr, dci->fde_encoding, &dci->start_ip, 0)) < 0)
		return ret;

	/* IP-range has same encoding as FDE pointers, except that it's
	   always an absolute value: */
	if ((ret = dwarf_read_encoded_pointer_local(as, &addr, dci->fde_encoding & DW_EH_PE_FORMAT_MASK, &dci->ip_range, 0)) < 0)
		return ret;

	if (dci->sized_augmentation) {
		arch_addr_t aug_size;

		if ((ret = dwarf_read_uleb128(NULL, &addr, &aug_size)) < 0)
			return ret;

		dci->fde_instr_start = addr + aug_size;
	}
	else
		dci->fde_instr_start = addr;
	dci->fde_instr_end = fde_end_addr;

	if ((ret = dwarf_read_encoded_pointer_local(as, &addr, dci->lsda_encoding, NULL, dci->start_ip)) < 0)
		return ret;

	if (dci->have_abi_marker) {
		if ((ret = dwarf_read16(NULL, &addr, &dci->abi)) < 0 || (ret = dwarf_read16(NULL, &addr, &dci->tag)) < 0)
			return ret;
	}

	return 0;
}

static int lib_addr_match(struct library *lib, arch_addr_t ip)
{
	if (!lib)
		return 0;

	return ip >= lib->load_addr && ip < lib->load_addr + lib->load_size;
}

int dwarf_locate_map(struct dwarf_addr_space *as, arch_addr_t ip)
{
	struct task *leader;
	struct list_head *it;

	if (lib_addr_match(as->cursor.lib, ip))
		return 0;

	leader = as->task->leader;

	as->cursor.lib = NULL;

	list_for_each(it, &leader->libraries_list) {
		struct library *lib = container_of(it, struct library, list);

		if (lib_addr_match(lib, ip)) {
			as->cursor.lib = lib;
			break;
		}
	}

	if (!as->cursor.lib) {
		debug(DEBUG_DWARF, "no mapping found for IP %#lx", ip);
		return -DWARF_ENOINFO;
	}

	return 0;
}

static const struct table_entry *lookup(const struct table_entry *table, size_t table_len, int32_t rel_ip)
{
	const struct table_entry *e, *f;
	unsigned long lo, hi;

	if (!table_len)
		return NULL;

	lo = 0;
	hi = table_len;
	f = NULL;
	do {
		unsigned long mid = (lo + hi) / 2;

		e = table + mid;

		if (rel_ip < e->start_ip_offset)
			hi = mid;
		else {
			f = e;
			lo = mid + 1;
		}
	} while(lo < hi);

	return f;
}

static int dwarf_search_unwind_table(struct dwarf_addr_space *as, arch_addr_t ip, void *table_data, unsigned long table_len)
{
	const struct table_entry *e;
	void *fde_addr;
	int ret;
	struct dwarf_cie_info *dci = &as->cursor.dci;
	struct library *lib = as->cursor.lib;

	e = lookup(table_data, table_len, ip - lib->load_addr - lib->seg_offset);
	if (!e) {
		/* IP is inside this table's range, but there is no explicit unwind info. */
		debug(DEBUG_DWARF, "no unwind info found for IP %#lx", ip);
		return -DWARF_ENOINFO;
	}

	fde_addr = lib->image_addr - lib->load_offset + e->fde_offset + lib->seg_offset;

	if ((ret = dwarf_extract_cfi_from_fde(as, fde_addr)) < 0)
		return ret;

	dci->start_ip -= ARCH_ADDR_T(lib->image_addr) - lib->load_addr;

	if (!as->task->is_64bit)
		dci->start_ip = (uint32_t)dci->start_ip;

	if (ip < dci->start_ip || ip >= dci->start_ip + dci->ip_range) {
		debug(DEBUG_DWARF, "IP %#lx out of range %#lx-%#lx", ip, dci->start_ip, dci->start_ip + dci->ip_range);
		return -DWARF_ENOINFO;
	}

	return 0;
}

static int dwarf_access_reg(struct dwarf_addr_space *as, unsigned int reg, arch_addr_t *valp)
{
	int map = dwarf_arch_map_reg(as, reg);

	if (map < 0) {
		debug(DEBUG_DWARF, "could not map register %u", reg);

		return map;
	}

	*valp = fetch_reg(as->task, map);

	return 0;
}

int dwarf_get(struct dwarf_addr_space *as, struct dwarf_loc loc, arch_addr_t *valp)
{
	arch_addr_t val = DWARF_GET_LOC(loc);

	if (DWARF_IS_REG_LOC(loc))
		return dwarf_access_reg(as, val, valp);

	if (!as->task->is_64bit)
		val &= 0xffffffff;

	if (DWARF_IS_MEM_LOC(loc))
		return dwarf_readw(as, &val, valp, as->task->is_64bit);

	*valp = val;
	return 0;
}

static int err_inval_reg_num(unsigned int regnum)
{
	debug(DEBUG_DWARF, "Invalid register number %u", regnum);
	return -DWARF_EBADREG;
}

static int dwarf_get_reg(struct dwarf_addr_space *as, unsigned int reg, arch_addr_t *valp)
{
	struct dwarf_cursor *c = &as->cursor;

	if (reg >= as->num_regs)
		return err_inval_reg_num((unsigned int)*valp);

	if (as->ip_reg == reg) {
		*valp = c->ip;
		return 0;
	}

	if (as->ret_reg == reg) {
		*valp = c->cfa;
		return 0;
	}

	return dwarf_get(as, c->loc[reg], valp);
}

static inline int read_regnum(unsigned int num_regs, arch_addr_t *addr, arch_addr_t *valp)
{
	int ret;
	arch_addr_t val;

	if ((ret = dwarf_read_uleb128(NULL, addr, &val)) < 0)
		return ret;

	val = dwarf_to_regnum(val);

	if (val >= num_regs)
		return err_inval_reg_num(val);

	*valp = val;

	return 0;
}

static inline void set_reg(struct dwarf_reg_state *rs, unsigned int regnum, enum dwarf_where where, arch_addr_t val)
{
	rs->reg[regnum].where = where;
	rs->reg[regnum].val = val;
}

static inline unsigned int regs_size(struct dwarf_addr_space *as)
{
	return sizeof(struct dwarf_reg_state) + sizeof(struct dwarf_reg) * as->num_regs;
}

static int run_cfi_program(struct dwarf_addr_space *as, struct dwarf_reg_state *rs_initial, struct dwarf_reg_state *rs_current, arch_addr_t ip, arch_addr_t *addr, arch_addr_t end_addr)
{
	arch_addr_t curr_ip, operand = 0, regnum, val, n;
	uint8_t u8, op;
	uint16_t u16;
	uint32_t u32;
	int ret;
	struct dwarf_cursor *c = &as->cursor;
	struct dwarf_cie_info *dci = &c->dci;
	unsigned int num_regs = as->num_regs;
	struct dwarf_reg_stack {
		struct dwarf_reg_stack *next;	/* for reg state stack */
		struct dwarf_reg_state store;
	} *rs_stack = NULL, *rs_tmp;

	curr_ip = dci->start_ip;

	/* Process everything up to and including the current 'ip',
	   including all the DW_CFA_advance_loc instructions. */
	while (curr_ip <= ip && *addr < end_addr) {
		if ((ret = dwarf_read8(NULL, addr, &op)) < 0)
			return ret;

		if (op & DWARF_CFA_OPCODE_MASK) {
			operand = op & DWARF_CFA_OPERAND_MASK;
			op &= ~DWARF_CFA_OPERAND_MASK;
		}
		switch (op) {
		case DW_CFA_advance_loc:
			curr_ip += operand * dci->code_align;
			break;
		case DW_CFA_advance_loc1:
			if ((ret = dwarf_read8(NULL, addr, &u8)) < 0)
				goto fail;
			curr_ip += u8 * dci->code_align;
			break;
		case DW_CFA_advance_loc2:
			if ((ret = dwarf_read16(NULL, addr, &u16)) < 0)
				goto fail;
			curr_ip += u16 * dci->code_align;
			break;
		case DW_CFA_advance_loc4:
			if ((ret = dwarf_read32(NULL, addr, &u32)) < 0)
				goto fail;
			curr_ip += u32 * dci->code_align;
			break;
		case DW_CFA_MIPS_advance_loc8:
			debug(DEBUG_DWARF, "Unexpected DW_CFA_MIPS_advance_loc8");
			ret = -DWARF_EINVAL;
			goto fail;
		case DW_CFA_offset:
			regnum = dwarf_to_regnum(operand);
			if (regnum >= num_regs) {
				debug(DEBUG_DWARF, "Invalid register number %u in DW_cfa_OFFSET", (unsigned int)regnum);
				ret = -DWARF_EBADREG;
				goto fail;
			}
			if ((ret = dwarf_read_uleb128(NULL, addr, &val)) < 0)
				goto fail;
			set_reg(rs_current, regnum, DWARF_WHERE_CFAREL, val * dci->data_align);
			break;
		case DW_CFA_offset_extended:
			if (((ret = read_regnum(num_regs, addr, &regnum)) < 0)
			    || ((ret = dwarf_read_uleb128(NULL, addr, &val)) < 0))
				goto fail;
			set_reg(rs_current, regnum, DWARF_WHERE_CFAREL, val * dci->data_align);
			break;
		case DW_CFA_offset_extended_sf:
			if (((ret = read_regnum(num_regs, addr, &regnum)) < 0)
			    || ((ret = dwarf_read_sleb128(NULL, addr, &val)) < 0))
				goto fail;
			set_reg(rs_current, regnum, DWARF_WHERE_CFAREL, val * dci->data_align);
			break;
		case DW_CFA_restore:
			regnum = dwarf_to_regnum(operand);
			if (regnum >= num_regs) {
				debug(DEBUG_DWARF, "Invalid register number %u in DW_CFA_restore", (unsigned int)regnum);
				ret = -DWARF_EINVAL;
				goto fail;
			}
			rs_current->reg[regnum] = rs_initial->reg[regnum];
			break;
		case DW_CFA_restore_extended:
			if ((ret = dwarf_read_uleb128(NULL, addr, &regnum)) < 0)
				goto fail;
			if (regnum >= num_regs) {
				debug(DEBUG_DWARF, "Invalid register number %u in " "DW_CFA_restore_extended", (unsigned int)regnum);
				ret = -DWARF_EINVAL;
				goto fail;
			}
			rs_current->reg[regnum] = rs_initial->reg[regnum];
			break;
		case DW_CFA_nop:
			break;
		case DW_CFA_set_loc:
			if ((ret = dwarf_read_encoded_pointer_local(as, addr, dci->fde_encoding, &curr_ip, c->dci.start_ip)) < 0)
				goto fail;
			break;
		case DW_CFA_undefined:
			if ((ret = read_regnum(num_regs, addr, &regnum)) < 0)
				goto fail;
			set_reg(rs_current, regnum, DWARF_WHERE_UNDEF, 0);
			break;
		case DW_CFA_same_value:
			if ((ret = read_regnum(num_regs, addr, &regnum)) < 0)
				goto fail;
			set_reg(rs_current, regnum, DWARF_WHERE_SAME, 0);
			break;
		case DW_CFA_register:
			if ((ret = read_regnum(num_regs, addr, &regnum)) < 0)
				goto fail;
			if ((ret = dwarf_read_uleb128(NULL, addr, &val)) < 0)
				goto fail;
			n = dwarf_to_regnum(val);
			if (n >= num_regs) {
				debug(DEBUG_DWARF, "Invalid register number value %u in DW_CFA_REGISTER", (unsigned int)val);
				ret = -DWARF_EBADREG;
				goto fail;
			}
			set_reg(rs_current, regnum, DWARF_WHERE_REG, n);
			break;
		case DW_CFA_remember_state:
			rs_tmp = malloc(regs_size(as));
			memcpy(&rs_tmp->store, rs_current, regs_size(as));
			rs_tmp->next = rs_stack;
			rs_stack = rs_tmp;
			break;
		case DW_CFA_restore_state:
			if (!rs_stack) {
				debug(DEBUG_DWARF, "register-state stack underflow");
				ret = -DWARF_EINVAL;
				goto fail;
			}
			rs_tmp = rs_stack;
			memcpy(rs_current, &rs_tmp->store, regs_size(as));
			rs_stack = rs_tmp->next;
			free(rs_tmp);
			break;
		case DW_CFA_def_cfa:
			if (((ret = read_regnum(num_regs, addr, &regnum)) < 0)
			    || ((ret = dwarf_read_uleb128(NULL, addr, &val)) < 0))
				goto fail;
			set_reg(rs_current, DWARF_CFA_REG_COLUMN(as), DWARF_WHERE_REG, regnum);
			set_reg(rs_current, DWARF_CFA_OFF_COLUMN(as), 0, val);				/* NOT factored! */
			break;
		case DW_CFA_def_cfa_sf:
			if (((ret = read_regnum(num_regs, addr, &regnum)) < 0)
			    || ((ret = dwarf_read_sleb128(NULL, addr, &val)) < 0))
				goto fail;
			set_reg(rs_current, DWARF_CFA_REG_COLUMN(as), DWARF_WHERE_REG, regnum);
			set_reg(rs_current, DWARF_CFA_OFF_COLUMN(as), 0, val * dci->data_align);	/* factored! */
			break;
		case DW_CFA_def_cfa_register:
			if ((ret = read_regnum(num_regs, addr, &regnum)) < 0)
				goto fail;
			set_reg(rs_current, DWARF_CFA_REG_COLUMN(as), DWARF_WHERE_REG, regnum);
			break;
		case DW_CFA_def_cfa_offset:
			if ((ret = dwarf_read_uleb128(NULL, addr, &val)) < 0)
				goto fail;
			set_reg(rs_current, DWARF_CFA_OFF_COLUMN(as), 0, val);	/* NOT factored! */
			break;
		case DW_CFA_def_cfa_offset_sf:
			if ((ret = dwarf_read_sleb128(NULL, addr, &val)) < 0)
				goto fail;
			set_reg(rs_current, DWARF_CFA_OFF_COLUMN(as), 0, val * dci->data_align);	/* factored! */
			break;
		case DW_CFA_def_cfa_expression:
			/* Save the address of the DW_FORM_block for later evaluation. */
			set_reg(rs_current, DWARF_CFA_REG_COLUMN(as), DWARF_WHERE_EXPR, *addr);

			if ((ret = dwarf_read_uleb128(NULL, addr, &n)) < 0)
				goto fail;

			*addr += n;
			break;
		case DW_CFA_expression:
			if ((ret = read_regnum(num_regs, addr, &regnum)) < 0)
				goto fail;

			/* Save the address of the DW_FORM_block for later evaluation. */
			set_reg(rs_current, regnum, DWARF_WHERE_EXPR, *addr);

			if ((ret = dwarf_read_uleb128(NULL, addr, &n)) < 0)
				goto fail;

			*addr += n;
			break;
		case DW_CFA_val_expression:
			if ((ret = read_regnum(num_regs, addr, &regnum)) < 0)
				goto fail;

			/* Save the address of the DW_FORM_block for later evaluation. */
			set_reg(rs_current, regnum, DWARF_WHERE_VAL_EXPR, *addr);

			if ((ret = dwarf_read_uleb128(NULL, addr, &n)) < 0)
				goto fail;

			*addr += n;
			break;
		case DW_CFA_GNU_args_size:
			if ((ret = dwarf_read_uleb128(NULL, addr, &val)) < 0)
				goto fail;
			break;
		case DW_CFA_GNU_negative_offset_extended:
			/* A comment in GCC says that this is obsoleted by
			   DW_CFA_offset_extended_sf, but that it's used by older
			   PowerPC code.  */
			if (((ret = read_regnum(num_regs, addr, &regnum)) < 0)
			    || ((ret = dwarf_read_uleb128(NULL, addr, &val)) < 0))
				goto fail;
			set_reg(rs_current, regnum, DWARF_WHERE_CFAREL, -(val * dci->data_align));
			break;
		case DW_CFA_GNU_window_save:
			/* FALL THROUGH */
		case DW_CFA_lo_user:
		case DW_CFA_hi_user:
			debug(DEBUG_DWARF, "Unexpected CFA opcode 0x%x", op);
			ret = -DWARF_EINVAL;
			goto fail;
		}
	}
	ret = 0;

fail:
	/* Free the register-state stack, if not empty already.  */
	while (rs_stack) {
		rs_tmp = rs_stack;
		rs_stack = rs_stack->next;
		free(rs_tmp);
	}
	return ret;
}

static int parse_fde(struct dwarf_addr_space *as, arch_addr_t ip, struct dwarf_reg_state *rs_current)
{
	arch_addr_t addr;
	int ret;
	struct dwarf_cursor *c = &as->cursor;
	struct dwarf_cie_info *dci = &c->dci;
	unsigned int i;
	struct dwarf_reg_state *rs_initial;

	if (dci->ret_addr_column >= as->num_regs) {
		debug(DEBUG_DWARF, "Invalid return address column %lu", dci->ret_addr_column);
		return -DWARF_EBADREG;
	}

	for (i = 0; i < as->num_regs; ++i)
		set_reg(rs_current, i, DWARF_WHERE_SAME, 0);

	set_reg(rs_current, DWARF_CFA_REG_COLUMN(as), DWARF_WHERE_SAME, 0);
	set_reg(rs_current, DWARF_CFA_OFF_COLUMN(as), DWARF_WHERE_SAME, 0);

	c->ret_addr_column = dci->ret_addr_column;

	rs_initial = alloca(regs_size(as));

	memset(rs_initial, 0, regs_size(as));

	addr = dci->cie_instr_start;
	if ((ret = run_cfi_program(as, rs_initial, rs_current, ~(arch_addr_t) 0, &addr, dci->cie_instr_end)) < 0)
		return ret;

	memcpy(rs_initial, rs_current, regs_size(as));

	addr = dci->fde_instr_start;
	if ((ret = run_cfi_program(as, rs_initial, rs_current, ip, &addr, dci->fde_instr_end)) < 0)
		return ret;

	return 0;
}

static long sword(struct dwarf_addr_space *as, arch_addr_t val)
{
	if (as->task->is_64bit)
		return (int64_t)val;
	else
		return (int32_t)val;
}

static arch_addr_t read_operand(struct dwarf_addr_space *as, arch_addr_t *addr, int operand_type, arch_addr_t *valp)
{
	union {
		uint8_t u8;
		uint16_t u16;
		uint32_t u32;
		uint64_t u64;
	} tmp;
	int ret;

	if (operand_type == ADDR) {
		if (as->task->is_64bit)
			operand_type = VAL64;
		else
			operand_type = VAL32;
	}

	switch (operand_type) {
	case VAL8:
		ret = dwarf_read8(NULL, addr, &tmp.u8);
		if (ret < 0)
			return ret;
		*valp = tmp.u8;
		break;
	case VAL16:
		ret = dwarf_read16(NULL, addr, &tmp.u16);
		if (ret < 0)
			return ret;
		*valp = tmp.u16;
		break;
	case VAL32:
		ret = dwarf_read32(NULL, addr, &tmp.u32);
		if (ret < 0)
			return ret;
		*valp = tmp.u32;
		break;
	case VAL64:
		ret = dwarf_read64(NULL, addr, &tmp.u64);
		if (ret < 0)
			return ret;
		*valp = tmp.u64;
		break;
	case ULEB128:
		ret = dwarf_read_uleb128(NULL, addr, valp);
		break;
	case SLEB128:
		ret = dwarf_read_sleb128(NULL, addr, valp);
		break;
	case OFFSET:		/* only used by DW_OP_call_ref, which we don't implement */
	default:
		debug(DEBUG_DWARF, "Unexpected operand type %d", operand_type);
		ret = -DWARF_EINVAL;
	}
	return ret;
}

static int dwarf_eval_expr(struct dwarf_addr_space *as, arch_addr_t addr, struct dwarf_loc *locp)
{
	arch_addr_t operand1 = 0, operand2 = 0, tmp1, tmp2, tmp3, end_addr;
	uint8_t opcode, operands_signature, u8;
	struct dwarf_cursor *c = &as->cursor;
	arch_addr_t stack[MAX_EXPR_STACK_SIZE];
	unsigned int tos = 0;
	uint16_t u16;
	uint32_t u32;
	uint64_t u64;
	int ret;
	arch_addr_t len, val;

#define pop()                                     \
({                                                \
  if ((tos - 1) >= MAX_EXPR_STACK_SIZE)           \
    {                                             \
      debug(DEBUG_DWARF, "Stack underflow");      \
      return -DWARF_EINVAL;                       \
    }                                             \
  stack[--tos];                                   \
})

#define push(x)                                   \
do {                                              \
  arch_addr_t _x = (x);                           \
  if (tos >= MAX_EXPR_STACK_SIZE)                 \
    {                                             \
      debug(DEBUG_DWARF, "Stack overflow");       \
      return -DWARF_EINVAL;                       \
    }                                             \
  stack[tos++] = _x;                              \
} while (0)

#define pick(n)                                   \
({                                                \
  unsigned int _index = tos - 1 - (n);            \
  if (_index >= MAX_EXPR_STACK_SIZE)              \
    {                                             \
      debug(DEBUG_DWARF, "Out-of-stack pick");    \
      return -DWARF_EINVAL;                       \
    }                                             \
  stack[_index];                                  \
})

	/* read the length of the expression: */
	if ((ret = dwarf_read_uleb128(NULL, &addr, &len)) < 0)
		return ret;

	end_addr = addr + len;

	push(c->cfa);		/* push current CFA as required by DWARF spec */

	while (addr < end_addr) {
		if ((ret = dwarf_read8(NULL, &addr, &opcode)) < 0)
			return ret;

		operands_signature = dwarf_operands[opcode];

		if (NUM_OPERANDS(operands_signature) > 0) {
			if ((ret = read_operand(as, &addr, OPND1_TYPE(operands_signature), &operand1)) < 0)
				return ret;
			if (NUM_OPERANDS(operands_signature) > 1)
				if ((ret = read_operand(as, &addr, OPND2_TYPE(operands_signature), &operand2)) < 0)
					return ret;
		}

		switch ((enum dwarf_expr_op) opcode) {
		case DW_OP_lit0 ... DW_OP_lit31:
			push(opcode - DW_OP_lit0);
			break;
		case DW_OP_breg0 ... DW_OP_breg31:
			if ((ret = dwarf_get_reg(as, dwarf_to_regnum(opcode - DW_OP_breg0), &tmp1)) < 0)
				return ret;
			push(tmp1 + operand1);
			break;
		case DW_OP_bregx:
			if ((ret = dwarf_get_reg(as, dwarf_to_regnum(operand1), &tmp1)) < 0)
				return ret;
			push(tmp1 + operand2);
			break;
		case DW_OP_reg0 ... DW_OP_reg31:
			val = opcode - DW_OP_reg0;
			*locp = DWARF_REG_LOC(val);
			return 0;
		case DW_OP_regx:
			val = operand1;
			*locp = DWARF_REG_LOC(val);
			return 0;
		case DW_OP_addr:
		case DW_OP_const1u:
		case DW_OP_const2u:
		case DW_OP_const4u:
		case DW_OP_const8u:
		case DW_OP_constu:
		case DW_OP_const8s:
		case DW_OP_consts:
			push(operand1);
			break;
		case DW_OP_const1s:
			if (operand1 & 0x80)
				operand1 |= ((arch_addr_t) - 1) << 8;
			push(operand1);
			break;
		case DW_OP_const2s:
			if (operand1 & 0x8000)
				operand1 |= ((arch_addr_t) - 1) << 16;
			push(operand1);
			break;
		case DW_OP_const4s:
			if (operand1 & 0x80000000)
				operand1 |= (((arch_addr_t) - 1) << 16) << 16;
			push(operand1);
			break;
		case DW_OP_deref:
			tmp1 = pop();
			if ((ret = dwarf_readw(as, &tmp1, &tmp2, as->task->is_64bit)) < 0)
				return ret;
			push(tmp2);
			break;
		case DW_OP_deref_size:
			tmp1 = pop();
			switch (operand1) {
			default:
				debug(DEBUG_DWARF, "Unexpected DW_OP_deref_size size %d", (int)operand1);
				return -DWARF_EINVAL;
			case 1:
				if ((ret = dwarf_read8(as, &tmp1, &u8)) < 0)
					return ret;
				tmp2 = u8;
				break;
			case 2:
				if ((ret = dwarf_read16(as, &tmp1, &u16)) < 0)
					return ret;
				tmp2 = u16;
				break;
			case 3:
			case 4:
				if ((ret = dwarf_read32(as, &tmp1, &u32)) < 0)
					return ret;
				tmp2 = u32;
				if (operand1 == 3) {
#if __BYTE_ORDER == __ORDER_LITTLE_ENDIAN
					tmp2 &= 0xffffff;
#else
					tmp2 >>= 8;
#endif
				}
				break;
			case 5:
			case 6:
			case 7:
			case 8:
				if ((ret = dwarf_read64(as, &tmp1, &u64)) < 0)
					return ret;
				tmp2 = u64;
				if (operand1 != 8) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
					tmp2 &= (~(arch_addr_t) 0) << (8 * operand1);
#else
					tmp2 >>= 64 - 8 * operand1;
#endif
				}
				break;
			}
			push(tmp2);
			break;

		case DW_OP_dup:
			push(pick(0));
			break;
		case DW_OP_drop:
			(void)pop();
			break;
		case DW_OP_pick:
			push(pick(operand1));
			break;
		case DW_OP_over:
			push(pick(1));
			break;
		case DW_OP_swap:
			tmp1 = pop();
			tmp2 = pop();
			push(tmp1);
			push(tmp2);
			break;
		case DW_OP_rot:
			tmp1 = pop();
			tmp2 = pop();
			tmp3 = pop();
			push(tmp1);
			push(tmp3);
			push(tmp2);
			break;
		case DW_OP_abs:
			tmp1 = pop();
			if (tmp1 & ((arch_addr_t) 1 << (8 * DWARF_ADDR_SIZE(as) - 1)))
				tmp1 = -tmp1;
			push(tmp1);
			break;
		case DW_OP_and:
			tmp1 = pop();
			tmp2 = pop();
			push(tmp1 & tmp2);
			break;
		case DW_OP_div:
			tmp1 = pop();
			tmp2 = pop();
			if (tmp1)
				tmp1 = sword(as, tmp2) / sword(as, tmp1);
			push(tmp1);
			break;
		case DW_OP_minus:
			tmp1 = pop();
			tmp2 = pop();
			tmp1 = tmp2 - tmp1;
			push(tmp1);
			break;
		case DW_OP_mod:
			tmp1 = pop();
			tmp2 = pop();
			if (tmp1)
				tmp1 = tmp2 % tmp1;
			push(tmp1);
			break;
		case DW_OP_mul:
			tmp1 = pop();
			tmp2 = pop();
			if (tmp1)
				tmp1 = tmp2 * tmp1;
			push(tmp1);
			break;
		case DW_OP_neg:
			push(-pop());
			break;
		case DW_OP_not:
			push(~pop());
			break;
		case DW_OP_or:
			tmp1 = pop();
			tmp2 = pop();
			push(tmp1 | tmp2);
			break;
		case DW_OP_plus:
			tmp1 = pop();
			tmp2 = pop();
			push(tmp1 + tmp2);
			break;
		case DW_OP_plus_uconst:
			tmp1 = pop();
			push(tmp1 + operand1);
			break;
		case DW_OP_shl:
			tmp1 = pop();
			tmp2 = pop();
			push(tmp2 << tmp1);
			break;
		case DW_OP_shr:
			tmp1 = pop();
			tmp2 = pop();
			push(tmp2 >> tmp1);
			break;
		case DW_OP_shra:
			tmp1 = pop();
			tmp2 = pop();
			push(sword(as, tmp2) >> tmp1);
			break;
		case DW_OP_xor:
			tmp1 = pop();
			tmp2 = pop();
			push(tmp1 ^ tmp2);
			break;
		case DW_OP_le:
			tmp1 = pop();
			tmp2 = pop();
			push(sword(as, tmp2) <= sword(as, tmp1));
			break;
		case DW_OP_ge:
			tmp1 = pop();
			tmp2 = pop();
			push(sword(as, tmp2) >= sword(as, tmp1));
			break;
		case DW_OP_eq:
			tmp1 = pop();
			tmp2 = pop();
			push(sword(as, tmp2) == sword(as, tmp1));
			break;
		case DW_OP_lt:
			tmp1 = pop();
			tmp2 = pop();
			push(sword(as, tmp2) < sword(as, tmp1));
			break;
		case DW_OP_gt:
			tmp1 = pop();
			tmp2 = pop();
			push(sword(as, tmp2) > sword(as, tmp1));
			break;
		case DW_OP_ne:
			tmp1 = pop();
			tmp2 = pop();
			push(sword(as, tmp2) != sword(as, tmp1));
			break;
		case DW_OP_skip:
			addr += (int16_t) operand1;
			break;
		case DW_OP_bra:
			tmp1 = pop();
			if (tmp1)
				addr += (int16_t) operand1;
			break;
		case DW_OP_nop:
			break;
		case DW_OP_call2:
		case DW_OP_call4:
		case DW_OP_call_ref:
		case DW_OP_fbreg:
		case DW_OP_piece:
		case DW_OP_push_object_address:
		case DW_OP_xderef:
		case DW_OP_xderef_size:
		default:
			debug(DEBUG_DWARF, "Unexpected opcode 0x%x", opcode);
			return -DWARF_EINVAL;
		}
	}
	val = pop();

	*locp = DWARF_MEM_LOC(val);
	return 0;
}

static int apply_reg_state(struct dwarf_addr_space *as, struct dwarf_reg_state *rs)
{
	arch_addr_t addr, cfa, ip;
	arch_addr_t prev_ip, prev_cfa;
	struct dwarf_loc cfa_loc;
	unsigned int i;
	int ret;
	struct dwarf_cursor *c = &as->cursor;

	prev_ip = c->ip;
	prev_cfa = c->cfa;

	/* Evaluate the CFA first, because it may be referred to by other
	   expressions.  */

	if (rs->reg[DWARF_CFA_REG_COLUMN(as)].where == DWARF_WHERE_REG) {
		/* CFA is equal to [reg] + offset: */

		/* As a special-case, if the stack-pointer is the CFA and the
		   stack-pointer wasn't saved, popping the CFA implicitly pops
		   the stack-pointer as well.  */
		if ((rs->reg[DWARF_CFA_REG_COLUMN(as)].val == as->ret_reg) && (rs->reg[as->ret_reg].where == DWARF_WHERE_SAME)) {
			cfa = c->cfa;
		}
		else {
			if ((ret = dwarf_get_reg(as, rs->reg[DWARF_CFA_REG_COLUMN(as)].val, &cfa)) < 0)
				return ret;
		}
		cfa += rs->reg[DWARF_CFA_OFF_COLUMN(as)].val;
	} else {
		/* CFA is equal to EXPR: */
		assert(rs->reg[DWARF_CFA_REG_COLUMN(as)].where == DWARF_WHERE_EXPR);

		addr = rs->reg[DWARF_CFA_REG_COLUMN(as)].val;
		if ((ret = dwarf_eval_expr(as, addr, &cfa_loc)) < 0)
			return ret;

		/* the returned location better be a memory location... */
		if (DWARF_IS_REG_LOC(cfa_loc))
			return -DWARF_EBADFRAME;
		cfa = DWARF_GET_LOC(cfa_loc);
	}

	for (i = 0; i < as->num_regs; ++i) {
		switch(rs->reg[i].where) {
		case DWARF_WHERE_UNDEF:
			c->loc[i] = DWARF_NULL_LOC;
			break;
		case DWARF_WHERE_SAME:
			break;
		case DWARF_WHERE_CFAREL:
			c->loc[i] = DWARF_MEM_LOC(cfa + rs->reg[i].val);
			break;
		case DWARF_WHERE_REG:
			c->loc[i] = DWARF_REG_LOC(rs->reg[i].val);
			break;
		case DWARF_WHERE_EXPR:
			addr = rs->reg[i].val;
			if ((ret = dwarf_eval_expr(as, addr, c->loc + i)) < 0)
				return ret;
			break;
		case DWARF_WHERE_VAL_EXPR:
			addr = rs->reg[i].val;
			if ((ret = dwarf_eval_expr(as, addr, c->loc + i)) < 0)
				return ret;
			c->loc[i] = DWARF_VAL_LOC(DWARF_GET_LOC(c->loc[i]));
			break;
		}
	}

	c->cfa = cfa;
	/* DWARF spec says undefined return address location means end of stack. */
	if (DWARF_IS_NULL_LOC(c->loc[c->ret_addr_column])) {
		c->ip = 0;
	}
	else {
		ret = dwarf_get(as, c->loc[c->ret_addr_column], &ip);
		if (ret < 0)
			return ret;
		c->ip = ip;
	}

	if (c->ip == prev_ip && c->cfa == prev_cfa) {
		debug(DEBUG_DWARF, "%s: ip and cfa unchanged; stopping here (ip=0x%lx)", __FUNCTION__, (long)c->ip);
		return -DWARF_EBADFRAME;
	}

	return 0;
}

static int fetch_proc_info(struct dwarf_addr_space *as, arch_addr_t ip)
{
	struct dwarf_cursor *c = &as->cursor;
	struct library *lib = c->lib;
	int ret;

	ret = dwarf_search_unwind_table(as, ip, lib->table_data, lib->table_len);
	if (ret < 0)
		return ret;

	/* Update use_prev_instr for the next frame. */
	c->use_prev_instr = !c->dci.signal_frame;

	return ret;
}

int dwarf_init_unwind(struct dwarf_addr_space *as)
{
	struct dwarf_cursor *c = &as->cursor;

	c->cfa = 0;
	c->ip = 0;
	c->ret_addr_column = 0;
	c->use_prev_instr = 0;
	c->valid = 1;
	c->lib = NULL;

	as->addr = 0;
	as->val = 0;

	memset(&c->dci, 0, sizeof(c->dci));

	return dwarf_arch_init_unwind(as);
}

void *dwarf_init(struct task *task)
{
	struct dwarf_addr_space *as;
	int ret;

	as = malloc(sizeof(*as));

	memset(as, 0, sizeof(*as));

	as->task = task;
	as->addr = 0;
	as->val = 0;

	ret = dwarf_arch_init(as);
	if (ret < 0) {
		free(as);
		return NULL;
	}

	as->cursor.loc = malloc(as->num_regs * sizeof(struct dwarf_reg));

	return as;
}

void dwarf_destroy(struct dwarf_addr_space *as)
{
	free(as->cursor.loc);
	free(as);
}

int dwarf_step(struct dwarf_addr_space *as)
{
	int ret;
	struct dwarf_cursor *c = &as->cursor;
	struct dwarf_reg_state *rs_current;
	arch_addr_t ip;

	if (!c->valid)
		return -DWARF_EINVAL;

	ip = c->ip;

	/* The 'ip' can point either to the previous or next instruction
	   depending on what type of frame we have: normal call or a place
	   to resume execution (e.g. after signal frame).

	   For a normal call frame we need to back up so we point within the
	   call itself; this is important because a) the call might be the
	   very last instruction of the function and the edge of the FDE,
	   and b) so that run_cfi_program() runs locations up to the call
	   but not more.

	   For execution resume, we need to do the exact opposite and look
	   up using the current 'ip' value.  That is where execution will
	   continue, and it's important we get this right, as 'ip' could be
	   right at the function entry and hence FDE edge, or at instruction
	   that manipulates CFA (push/pop). */
	if (c->use_prev_instr)
		--ip;

	ret = dwarf_locate_map(as, ip);
	if (ret < 0)
		goto fail;

	ret = fetch_proc_info(as, ip);
	if (ret < 0)
		goto fail;

	rs_current = alloca(regs_size(as));

	ret = parse_fde(as, ip, rs_current);
	if (ret < 0)
		goto fail;

	ret = apply_reg_state(as, rs_current);
	if (ret < 0)
		goto fail;

	return 0;

fail:
	if (ret == -DWARF_ENOINFO) {
		debug(DEBUG_DWARF, "try arch specific step");

		ret = dwarf_arch_step(as);
		if (!ret)
			ret = dwarf_locate_map(as, c->use_prev_instr ? c->ip - 1 : c->ip);
	}
	if (ret) {
		debug(DEBUG_DWARF, "error %d", ret);

		c->valid = 0;
	}

	return ret;
}

arch_addr_t dwarf_get_ip(struct dwarf_addr_space *as)
{
	struct dwarf_cursor *c = &as->cursor;

	if (!c->valid)
		return ARCH_ADDR_T(0);

	return c->ip;
}

int dwarf_get_unwind_table(struct task *task, struct library *lib, struct dwarf_eh_frame_hdr *hdr)
{
	arch_addr_t addr, fde_count;
	int ret;
	struct dwarf_addr_space tmp_as;

	memset(&tmp_as, 0, sizeof(tmp_as));

	tmp_as.task = task;
	tmp_as.cursor.lib = lib;

	if (hdr->version != DW_EH_VERSION) {
		debug(DEBUG_DWARF, "exception table has unexpected version %d", hdr->version);
		return -DWARF_ENOINFO;
	}

	addr = ARCH_ADDR_T(hdr + 1);

	/* (Optionally) read eh_frame_ptr: */
	if ((ret = dwarf_read_encoded_pointer_local(&tmp_as, &addr, hdr->eh_frame_ptr_enc, NULL, 0)) < 0)
		return -DWARF_ENOINFO;

	/* (Optionally) read fde_count: */
	if ((ret = dwarf_read_encoded_pointer_local(&tmp_as, &addr, hdr->fde_count_enc, &fde_count, 0)) < 0)
		return -DWARF_ENOINFO;

	if (hdr->table_enc != (DW_EH_PE_datarel | DW_EH_PE_sdata4)) {
		debug(DEBUG_DWARF, "unsupported unwind table encoding.");
		return -DWARF_EINVAL;
	}

	lib->table_data = (void *)addr;
	lib->table_len = fde_count;

	return 0;
}

