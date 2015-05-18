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

#ifndef _INC_MTRACE_ELF_H
#define _INC_MTRACE_ELF_H

#include <gelf.h>
#include <stdlib.h>

#include "forward.h"
#include "sysdep.h"

struct mt_elf {
	int fd;
	const char *filename;
	Elf *elf;
	GElf_Ehdr ehdr;
	Elf_Data *dynsym;
	size_t dynsym_count;
	const char *dynstr;
	Elf_Data *symtab;
	const char *strtab;
	size_t symtab_count;
	GElf_Addr dyn_addr;
	GElf_Addr bias;
	GElf_Addr entry_addr;
	GElf_Addr base_addr;
	GElf_Addr interp;
	GElf_Phdr txt_hdr;
	GElf_Phdr eh_hdr;
	GElf_Phdr dyn_hdr;
	GElf_Phdr exidx_hdr;
	GElf_Addr pltgot;
};

struct elf_image {
	void *addr;	/* pointer to mmap'd image */
	size_t size;	/* (file-) size of the image */
};

int elf_read_library(struct task *task, struct library *lib, const char *filename, GElf_Addr bias);

/* Create a library object representing the main binary. */
struct library *elf_read_main_binary(struct task *task);

#endif

