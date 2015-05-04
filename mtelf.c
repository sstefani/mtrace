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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "backend.h"
#include "breakpoint.h"
#include "dwarf.h"
#include "library.h"
#include "mtelf.h"
#include "task.h"
#include "debug.h"
#include "options.h"
#include "common.h"
#include "report.h"

static int open_elf(struct mt_elf *mte, const char *filename)
{
	mte->filename = filename;

	if (options.cwd != -1)
		mte->fd = openat(options.cwd, filename, O_RDONLY);
	else
		mte->fd = open(filename, O_RDONLY);

	if (mte->fd == -1)
		return 1;

	elf_version(EV_CURRENT);

#ifdef HAVE_ELF_C_READ_MMAP
	mte->elf = elf_begin(mte->fd, ELF_C_READ_MMAP, NULL);
#else
	mte->elf = elf_begin(mte->fd, ELF_C_READ, NULL);
#endif

	if (mte->elf == NULL || elf_kind(mte->elf) != ELF_K_ELF) {
		fprintf(stderr, "\"%s\" is not an ELF file\n", filename);
		exit(EXIT_FAILURE);
	}

	if (gelf_getehdr(mte->elf, &mte->ehdr) == NULL) {
		fprintf(stderr, "can't read ELF header of \"%s\": %s\n", filename, elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	if (mte->ehdr.e_type != ET_EXEC && mte->ehdr.e_type != ET_DYN) {
		fprintf(stderr, "\"%s\" is neither an ELF executable" " nor a shared library\n", filename);
		exit(EXIT_FAILURE);
	}

	if (1
#ifdef MT_ELF_MACHINE
	    && (mte->ehdr.e_ident[EI_CLASS] != MT_ELFCLASS || mte->ehdr.e_machine != MT_ELF_MACHINE)
#endif
#ifdef MT_ELF_MACHINE2
	    && (mte->ehdr.e_ident[EI_CLASS] != MT_ELFCLASS2 || mte->ehdr.e_machine != MT_ELF_MACHINE2)
#endif
#ifdef MT_ELF_MACHINE3
	    && (mte->ehdr.e_ident[EI_CLASS] != MT_ELFCLASS3 || mte->ehdr.e_machine != MT_ELF_MACHINE3)
#endif
	    ) {
		fprintf(stderr, "\"%s\" is ELF from incompatible architecture\n", filename);
		exit(EXIT_FAILURE);
	}

	return 0;
}

static void read_symbol_table(struct mt_elf *mte, const char *filename, Elf_Scn *scn, GElf_Shdr *shdr, const char *name, Elf_Data ** datap, size_t *countp, const char **strsp)
{
	*datap = elf_getdata(scn, NULL);
	*countp = shdr->sh_size / shdr->sh_entsize;
	if ((*datap == NULL || elf_getdata(scn, *datap) != NULL)) {
		fprintf(stderr, "Couldn't get data of section" " %s from \"%s\": %s\n", name, filename, elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	scn = elf_getscn(mte->elf, shdr->sh_link);
	GElf_Shdr shdr2;
	if (scn == NULL || gelf_getshdr(scn, &shdr2) == NULL) {
		fprintf(stderr, "Couldn't get header of section" " #%d from \"%s\": %s\n", shdr2.sh_link, filename, elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL || elf_getdata(scn, data) != NULL || shdr2.sh_size != data->d_size || data->d_off) {
		fprintf(stderr, "Couldn't get data of section" " #%d from \"%s\": %s\n", shdr2.sh_link, filename, elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	*strsp = data->d_buf;
}

static int populate_this_symtab(struct mt_elf *mte, struct library *lib, Elf_Data *symtab, const char *strtab, size_t size)
{
	size_t i;

	for (i = 0; i < size; ++i) {
		GElf_Sym sym;

		if (gelf_getsym(symtab, i, &sym) == NULL) {
			fprintf(stderr, "couldn't get symbol #%zd from %s: %s\n", i, mte->filename, elf_errmsg(-1));
			continue;
		}

		if (GELF_ST_TYPE(sym.st_info) != STT_FUNC || sym.st_value == 0 || sym.st_shndx == STN_UNDEF)
			continue;

		/* Find symbol name and snip version. */
		const char *orig_name = strtab + sym.st_name;
		const char *version = strchr(orig_name, '@');
		size_t len = version ? (size_t)(version - orig_name) : strlen(orig_name);
		char name[len + 1];

		memcpy(name, orig_name, len);
		name[len] = 0;

		/* If the symbol is not matched, skip it. */
		const struct function *func = flist_matches_symbol(name);
		if (!func)
			continue;

		arch_addr_t addr = ARCH_ADDR_T(sym.st_value + mte->bias);

		if (!library_find_symbol(lib, addr)) {
			struct library_symbol *libsym = library_symbol_new(lib, addr, func);

			if (!libsym) {
				fprintf(stderr, "couldn't init symbol: %s%s\n", name, func->name);
				continue;
			}
		}
	}

	return 0;
}

static int populate_symtab(struct mt_elf *mte, struct library *lib)
{
	if (mte->symtab != NULL && mte->strtab != NULL) {
		int status = populate_this_symtab(mte, lib, mte->symtab, mte->strtab, mte->symtab_count);

		if (status < 0)
			return status;
	}

	return populate_this_symtab(mte, lib, mte->dynsym, mte->dynstr, mte->dynsym_count);
}

static inline int elf_map_image(struct mt_elf *mte, void **image_addr)
{
	void *addr;

	addr = mmap(NULL, mte->txt_hdr.p_filesz, PROT_READ, MAP_PRIVATE, mte->fd, mte->txt_hdr.p_offset);
	if (addr == MAP_FAILED) {
		fprintf(stderr, "mmap failed\n");
		return -1;
	}

	*image_addr = addr;

	return 0;
}

static int elf_lib_init(struct mt_elf *mte, struct task *task, struct library *lib)
{
	if (elf_map_image(mte, &lib->image_addr))
		return -1;

	lib->base = ARCH_ADDR_T(mte->base_addr);
	lib->entry = ARCH_ADDR_T(mte->entry_addr);
	lib->load_offset = mte->txt_hdr.p_offset;
	lib->load_addr = mte->txt_hdr.p_vaddr + mte->bias;
	lib->load_size = mte->txt_hdr.p_filesz;
	lib->seg_offset = mte->eh_hdr.p_offset;
	lib->gp = mte->pltgot;

#ifdef __arm__
	if (mte->exidx_hdr.p_filesz) {
		lib->exidx_data = lib->image_addr + mte->exidx_hdr.p_offset;
		lib->exidx_len = mte->exidx_hdr.p_memsz;
	}
#endif

	if (mte->eh_hdr.p_filesz && mte->dyn_addr) {
		if (dwarf_get_unwind_table(task, lib, (struct dwarf_eh_frame_hdr *)(lib->image_addr - lib->load_offset + mte->eh_hdr.p_offset)) < 0)
			return -1;
	}

	if (populate_symtab(mte, lib) < 0)
		return -1;

	return 0;
}

static void close_elf(struct mt_elf *mte)
{
	if (mte->fd != -1) {
		elf_end(mte->elf);
		close(mte->fd);
	}
}

static int elf_read(struct mt_elf *mte, const char *filename, GElf_Addr bias)
{
	debug(DEBUG_FUNCTION, "filename=%s", filename);

	if (open_elf(mte, filename) < 0)
		return -1;

	GElf_Phdr phdr;
	int i;

	memset(&mte->txt_hdr, 0, sizeof(mte->txt_hdr));
	memset(&mte->eh_hdr, 0, sizeof(mte->eh_hdr));
	memset(&mte->dyn_hdr, 0, sizeof(mte->dyn_hdr));
	memset(&mte->exidx_hdr, 0, sizeof(mte->exidx_hdr));

	for (i = 0; gelf_getphdr(mte->elf, i, &phdr) != NULL; ++i) {

		switch (phdr.p_type) {
		case PT_LOAD:
			if (!mte->base_addr || mte->base_addr > phdr.p_vaddr + bias)
				mte->base_addr = phdr.p_vaddr + bias;

			if ((phdr.p_flags & (PF_X | PF_W)) == PF_X)
				mte->txt_hdr = phdr;
			break;
		case PT_GNU_EH_FRAME:
			mte->eh_hdr = phdr;
			break;
#ifdef __arm__
		case PT_ARM_EXIDX:
			mte->exidx_hdr = phdr;
			break;
#endif
		case PT_INTERP:
			mte->interp = phdr.p_vaddr + bias;
			break;
		default:
			break;
		}
	}

	if (!mte->base_addr) {
		fprintf(stderr, "Couldn't determine base address of %s\n", filename);
		return -1;
	}

	debug(DEBUG_FUNCTION, "filename=`%s' load_offset=%#llx addr=%#llx size=%#llx",
			filename,
			(unsigned long long)mte->txt_hdr.p_offset,
			(unsigned long long)mte->txt_hdr.p_vaddr + bias,
			(unsigned long long)mte->txt_hdr.p_filesz);

	for (i = 1; i < mte->ehdr.e_shnum; ++i) {
		Elf_Scn *scn;
		GElf_Shdr shdr;
		const char *name;

		scn = elf_getscn(mte->elf, i);
		if (scn == NULL || gelf_getshdr(scn, &shdr) == NULL) {
			fprintf(stderr, "Couldn't get section #%d from" " \"%s\": %s\n", i, filename, elf_errmsg(-1));
			exit(EXIT_FAILURE);
		}

		name = elf_strptr(mte->elf, mte->ehdr.e_shstrndx, shdr.sh_name);
		if (name == NULL) {
			fprintf(stderr, "Couldn't get name of section #%d from \"%s\": %s\n", i, filename, elf_errmsg(-1));
			exit(EXIT_FAILURE);
		}

		if (shdr.sh_type == SHT_SYMTAB) {
			read_symbol_table(mte, filename, scn, &shdr, name, &mte->symtab, &mte->symtab_count, &mte->strtab);
		} else if (shdr.sh_type == SHT_DYNSYM) {
			read_symbol_table(mte, filename, scn, &shdr, name, &mte->dynsym, &mte->dynsym_count, &mte->dynstr);
		} else if (shdr.sh_type == SHT_DYNAMIC) {
			Elf_Data *data;
			GElf_Dyn dyn;
			int idx;

			data = elf_getdata(scn, NULL);
			if (data == NULL) {
				fprintf(stderr, "Couldn't get .dynamic data from \"%s\": %s\n", filename, strerror(errno));
				exit(EXIT_FAILURE);
			}

			for(idx = 0; gelf_getdyn(data, idx, &dyn); ++idx) {
				if (dyn.d_tag == DT_PLTGOT)  {
					mte->pltgot = dyn.d_un.d_ptr;
					break;
				}
			}
			
			mte->dyn_addr = shdr.sh_addr + bias;
		}
	}

	if (!mte->dyn_addr) {
		fprintf(stderr, "Couldn't find .dynamic section \"%s\"\n", filename);
		exit(EXIT_FAILURE);
	}

	if (!mte->dynsym || !mte->dynstr) {
		fprintf(stderr, "Couldn't find .dynsym or .dynstr in \"%s\"\n", filename);
		exit(EXIT_FAILURE);
	}

	return 0;
}

int elf_read_library(struct task *task, struct library *lib, const char *filename, GElf_Addr bias)
{
	struct mt_elf mte = { };
	int ret;

	library_set_filename(lib, filename);

	if (elf_read(&mte, filename, bias) == -1)
		return -1;

	mte.bias = bias;
	mte.entry_addr = mte.ehdr.e_entry + bias;

	ret = elf_lib_init(&mte, task, lib);

	close_elf(&mte);

	return ret;
}

static arch_addr_t _find_solib_break(struct mt_elf *mte, Elf_Data *symtab, const char *strtab, size_t size)
{
	size_t i;
	unsigned int j;

	static const char * const solib_break_names[] =
	{
		"r_debug_state",
		"_r_debug_state",
		"_dl_debug_state",
		"rtld_db_dlactivity",
		"__dl_rtld_db_dlactivity",
		"_rtld_debug_state"
	};

	for (i = 0; i < size; ++i) {
		GElf_Sym sym;

		if (gelf_getsym(symtab, i, &sym) == NULL) {
			fprintf(stderr, "couldn't get symbol #%zd from %s: %s\n", i, mte->filename, elf_errmsg(-1));
			continue;
		}

		if (GELF_ST_TYPE(sym.st_info) != STT_FUNC || sym.st_value == 0 || sym.st_shndx == STN_UNDEF)
			continue;

		const char *name = strtab + sym.st_name;

		for(j = 0; j < ARRAY_SIZE(solib_break_names); j++) {
			if (!strcmp(name, solib_break_names[j]))
				return ARCH_ADDR_T(sym.st_value + mte->bias);
		}
	}
	return ARCH_ADDR_T(0);
}

static arch_addr_t find_solib_break(struct mt_elf *mte)
{
	if (mte->symtab && mte->strtab) {
		arch_addr_t addr = _find_solib_break(mte, mte->symtab, mte->strtab, mte->symtab_count);
		
		if (addr)
			return addr;
	}

	return _find_solib_break(mte, mte->dynsym, mte->dynstr, mte->dynsym_count);
}

struct entry_breakpoint {
	struct breakpoint breakpoint;	/* must the first element in the structure */
	arch_addr_t dyn_addr;
};


static int entry_breakpoint_on_hit(struct task *task, struct breakpoint *a)
{
	struct entry_breakpoint *entry_bp = (void *)a;

	if (!task)
		return 0;

	breakpoint_delete(task, &entry_bp->breakpoint);
	linkmap_init(task, entry_bp->dyn_addr);
	return 1;
}

struct library *elf_read_main_binary(struct task *task)
{
	char fname[PATH_MAX];
	int ret;
	char *filename;
	struct mt_elf mte = { };
	unsigned long entry;
	unsigned long base;
	struct library *lib;

	filename = pid2name(task->pid);
	if (!filename)
		return NULL;

	lib = library_new();
	if (lib == NULL)
		goto fail1;

	ret = readlink(filename, fname, sizeof(fname) - 1);
	if (ret == -1)
		goto fail2;

	fname[ret] = 0;

	library_set_filename(lib, strdup(fname));

	if (elf_read(&mte, filename, 0) == -1)
		goto fail3;

	task->is_64bit = is_64bit(&mte);

	if (process_get_entry(task, &entry, &base) < 0) {
		fprintf(stderr, "Couldn't find process entry of %s\n", filename);
		goto fail3;
	}

	free(filename);

	mte.bias = (GElf_Addr) (uintptr_t) entry - mte.ehdr.e_entry;
	mte.entry_addr = (GElf_Addr) (uintptr_t) entry;

	if (elf_lib_init(&mte, task, lib))
		goto fail3;

	close_elf(&mte);

	report_attach(task);

	library_add(task, lib);

	if (!linkmap_init(task, ARCH_ADDR_T(mte.dyn_addr)))
		return lib;

	if (!mte.interp)
		return lib;

	struct mt_elf mte_ld = { };

	copy_str_from_proc(task, ARCH_ADDR_T(mte.interp), fname, sizeof(fname));

	if (!elf_read(&mte_ld, fname, (GElf_Addr)base)) {
		mte_ld.bias = (GElf_Addr)base;
		mte_ld.entry_addr = mte_ld.ehdr.e_entry + (GElf_Addr)base;

		arch_addr_t addr = find_solib_break(&mte_ld);
		if (!addr)
			addr = ARCH_ADDR_T(entry);

		struct entry_breakpoint *entry_bp = (void *)breakpoint_new_ext(task, addr, NULL, 0, sizeof(*entry_bp) - sizeof(entry_bp->breakpoint));
		if (!entry_bp)
			fprintf(stderr,
				"Couldn't initialize entry breakpoint for PID %d.\n"
				"Some tracing events may be missed.\n",
				task->pid
			);
		else {
			entry_bp->breakpoint.on_hit = entry_breakpoint_on_hit;
			entry_bp->breakpoint.locked = 1;
			entry_bp->dyn_addr = ARCH_ADDR_T(mte.dyn_addr);

			breakpoint_enable(task, &entry_bp->breakpoint);
		}
	}
	close_elf(&mte_ld);

	return lib;
fail3:
	close_elf(&mte);
fail2:
	library_destroy(task, lib);
fail1:
	free(filename);
	return lib;
}

