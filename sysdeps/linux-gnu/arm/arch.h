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

#ifndef _INC_SYSDEPS_LINUX_GNU_ARM_ARCH_H
#define _INC_SYSDEPS_LINUX_GNU_ARM_ARCH_H

#include <elf.h>
#include <stddef.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>

#define BREAKPOINT_VALUE { 0xf0, 0x01, 0xf0, 0xe7 }
#define BREAKPOINT_LENGTH 4
#define THUMB_BREAKPOINT_VALUE { 0x01, 0xde }
#define THUMB_BREAKPOINT_LENGTH 2
#define DECR_PC_AFTER_BREAK 0
#define ARCH_HAVE_FETCH_ARG
#define ARCH_HAVE_SIZEOF
#define ARCH_HAVE_ALIGNOF
#define ARCH_ENDIAN_LITTLE
#define ARCH_HAVE_ATOMIC_SINGLESTEP

#define MT_ELFCLASS	ELFCLASS32
#define MT_ELF_MACHINE	EM_ARM

#define	ARCH_SINGLESTEP

#define DWARF_TO_REGNUM

#define HW_BREAKPOINTS	0

struct context {
	struct pt_regs regs;
};

#endif

