/*
 * This file is part of mtrace-ng.
 * Copyright (C) 2018 Stefani Seibold <stefani@seibold.net>
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

#define PAGESIZE	4096
#define PAGEALIGN	(PAGESIZE - 1)

struct mt_elf {
	int fd;
	const char *filename;
	Elf *elf;
	unsigned int loadsegs;
	GElf_Phdr loadseg[4];
	unsigned long loadbase;
	unsigned long loadsize;
	unsigned long vstart;
	GElf_Ehdr ehdr;
	Elf_Data *dynsym;
	size_t dynsym_count;
	const char *dynstr;
	Elf_Data *symtab;
	const char *strtab;
	size_t symtab_count;
	GElf_Addr bias;
	GElf_Addr entry_addr;
	GElf_Addr base_addr;
	GElf_Addr interp;
	GElf_Phdr txt_hdr;
	GElf_Phdr eh_hdr;
	GElf_Addr dyn;
	GElf_Phdr exidx_hdr;
	GElf_Addr pltgot;
};

static int open_elf(struct mt_elf *mte, struct task *task, const char *filename)
{
	char *cwd;

	mte->filename = filename;
	mte->fd = -1;

	cwd = pid2cwd(task->pid);
	if (cwd) {
		int fd = open(cwd, O_RDONLY|O_DIRECTORY);

		if (fd != -1) {
			mte->fd = openat(fd, filename, O_RDONLY);

			close(fd);
		}

		free(cwd);
	}

	if (mte->fd == -1) {
		if (options.cwd != -1)
			mte->fd = openat(options.cwd, filename, O_RDONLY);
		else
			mte->fd = open(filename, O_RDONLY);
	}

	if (mte->fd == -1) {
		fprintf(stderr, "could not open %s\n", filename);
		return -1;
	}

	elf_version(EV_CURRENT);

#ifdef HAVE_ELF_C_READ_MMAP
	mte->elf = elf_begin(mte->fd, ELF_C_READ_MMAP, NULL);
#else
	mte->elf = elf_begin(mte->fd, ELF_C_READ, NULL);
#endif

	if (mte->elf == NULL || elf_kind(mte->elf) != ELF_K_ELF) {
		fprintf(stderr, "\"%s\" is not an ELF file\n", filename);
		return -1;
	}

	if (gelf_getehdr(mte->elf, &mte->ehdr) == NULL) {
		fprintf(stderr, "can't read ELF header of \"%s\": %s\n", filename, elf_errmsg(-1));
		return -1;
	}

	if (mte->ehdr.e_type != ET_EXEC && mte->ehdr.e_type != ET_DYN) {
		fprintf(stderr, "\"%s\" is neither an ELF executable" " nor a shared library\n", filename);
		return -1;
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
		return -1;
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

static int populate_this_symtab(struct mt_elf *mte, struct libref *libref, Elf_Data *symtab, const char *strtab, size_t size)
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

		struct library_symbol *libsym = library_find_symbol(libref, addr);
		if (!libsym) {
			struct library_symbol *libsym = library_symbol_new(libref, addr, func);

			if (!libsym) {
				fprintf(stderr, "couldn't init symbol: %s%s\n", name, func->name);
				continue;
			}
		}
		else {
			/* handle symbol alias */
			if (libsym->func->level > func->level)
				libsym->func = func;
		}
		if (unlikely(options.verbose > 1))
			fprintf(stderr, "breakpoint for %s:%s at %#lx\n", libref->filename, func->demangled_name, addr);
	}

	return 0;
}

static int populate_symtab(struct mt_elf *mte, struct libref *libref)
{
	struct opt_O_t *p;

	for(p = options.opt_O; p; p = p->next) {
		if (!strcmp(p->pathname, libref->filename))
			return 0;
	}

	if (mte->symtab != NULL && mte->strtab != NULL) {
		int status = populate_this_symtab(mte, libref, mte->symtab, mte->strtab, mte->symtab_count);

		if (status < 0)
			return status;
	}

	return populate_this_symtab(mte, libref, mte->dynsym, mte->dynstr, mte->dynsym_count);
}

static inline int elf_map_image(struct mt_elf *mte, void **mmap_addr)
{
	void *addr;

	addr = mmap(NULL, mte->loadsize, PROT_READ, MAP_PRIVATE, mte->fd, mte->loadbase);
	if (addr == MAP_FAILED) {
		fprintf(stderr, "mmap failed\n");
		return -1;
	}

	*mmap_addr = addr;

	return 0;
}

static int elf_lib_init(struct mt_elf *mte, struct task *task, struct libref *libref)
{
	if (elf_map_image(mte, &libref->mmap_addr))
		return -1;

	libref->entry = ARCH_ADDR_T(mte->entry_addr);
	libref->mmap_offset = mte->loadbase;
	libref->mmap_size = mte->loadsize;
	libref->txt_vaddr = mte->txt_hdr.p_vaddr - mte->vstart + mte->bias;
	libref->txt_size = mte->txt_hdr.p_filesz;
	libref->txt_offset = mte->txt_hdr.p_offset - mte->loadbase;
	libref->bias = mte->bias;
	libref->eh_frame_hdr = mte->eh_hdr.p_offset - mte->loadbase;
	libref->pltgot = mte->pltgot;
	libref->dyn = mte->dyn - mte->vstart + mte->bias;
	libref->loadsegs = mte->loadsegs;

	for(unsigned int i = 0; i < libref->loadsegs; ++i)
		libref->loadseg[i] = mte->loadseg[i];

#ifdef __arm__
	if (mte->exidx_hdr.p_filesz) {
		libref->exidx_data = libref->mmap_addr + mte->exidx_hdr.p_offset - mte->loadbase;
		libref->exidx_len = mte->exidx_hdr.p_filesz;
	}
#endif

	if (mte->eh_hdr.p_filesz && mte->dyn) {
		if (dwarf_get_unwind_table(task, libref) < 0)
			return -1;
	}

	if (populate_symtab(mte, libref) < 0)
		return -1;

	return 0;
}

static void close_elf(struct mt_elf *mte)
{
	if (mte->fd != -1) {
		elf_end(mte->elf);
		close(mte->fd);

		mte->fd = -1;
		mte->filename = NULL;
	}
}

static int elf_read(struct mt_elf *mte, struct task *task, const char *filename)
{
	unsigned long loadsize = 0;
	unsigned long loadbase = ~0;
	unsigned long align;
	unsigned long vstart;

	debug(DEBUG_FUNCTION, "filename=%s", filename);

	if (open_elf(mte, task, filename) < 0)
		return -1;

	GElf_Phdr phdr;
	int i;

	memset(&mte->txt_hdr, 0, sizeof(mte->txt_hdr));
	memset(&mte->eh_hdr, 0, sizeof(mte->eh_hdr));
	memset(&mte->exidx_hdr, 0, sizeof(mte->exidx_hdr));

	mte->loadsegs = 0;

	for (i = 0; gelf_getphdr(mte->elf, i, &phdr) != NULL; ++i) {
		switch (phdr.p_type) {
		case PT_LOAD:
			if (mte->loadsegs >= ARRAY_SIZE(mte->loadseg)) {
				fprintf(stderr, "Unable to handle more than %lu loadable segments in %s\n", ARRAY_SIZE(mte->loadseg), filename);
				return -1;
			}

			mte->loadseg[mte->loadsegs++] = phdr;

			align = phdr.p_align;
			if (align)
				align -= 1;

			vstart = phdr.p_vaddr & ~align;

			if (mte->vstart > vstart)
				mte->vstart = vstart;

			if (loadbase > phdr.p_offset)
				loadbase = phdr.p_offset;

			if (loadsize < phdr.p_offset + phdr.p_filesz)
				loadsize = phdr.p_offset + phdr.p_filesz;

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
			mte->interp = phdr.p_vaddr;
			break;
		case PT_DYNAMIC:
			mte->dyn = phdr.p_vaddr;
			break;
		default:
			break;
		}
	}

	if (!mte->loadsegs) {
		fprintf(stderr, "No loadable segemnts in %s\n", filename);
		return -1;
	}

//fprintf(stderr, "%s:%d %s loadbase:%#lx loadsize:%#lx\n", __func__, __LINE__, filename, loadbase, loadsize);
	mte->loadbase = loadbase & ~PAGEALIGN;
	mte->loadsize = (loadsize + (loadbase - mte->loadbase) + PAGEALIGN) & ~PAGEALIGN;
fprintf(stderr, "%s:%d %s loadbase:%#lx loadsize:%#lx\n", __func__, __LINE__, mte->filename, mte->loadbase, mte->loadsize);

	debug(DEBUG_FUNCTION, "filename=`%s' text offset=%#llx addr=%#llx size=%#llx",
			filename,
			(unsigned long long)mte->txt_hdr.p_offset,
			(unsigned long long)mte->txt_hdr.p_vaddr,
			(unsigned long long)mte->txt_hdr.p_filesz);

	for (i = 1; i < mte->ehdr.e_shnum; ++i) {
		Elf_Scn *scn;
		GElf_Shdr shdr;
		const char *name;

		scn = elf_getscn(mte->elf, i);
		if (scn == NULL || gelf_getshdr(scn, &shdr) == NULL) {
			fprintf(stderr, "Couldn't get section #%d from" " \"%s\": %s\n", i, filename, elf_errmsg(-1));
			return -1;
		}

		name = elf_strptr(mte->elf, mte->ehdr.e_shstrndx, shdr.sh_name);
		if (name == NULL) {
			fprintf(stderr, "Couldn't get name of section #%d from \"%s\": %s\n", i, filename, elf_errmsg(-1));
			return -1;
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
				return -1;
			}

			for(idx = 0; gelf_getdyn(data, idx, &dyn); ++idx) {
				if (dyn.d_tag == DT_PLTGOT)  {
					mte->pltgot = dyn.d_un.d_ptr;
					break;
				}
			}
		}
	}

	if (!mte->dynsym || !mte->dynstr) {
		fprintf(stderr, "Couldn't find .dynsym or .dynstr in \"%s\"\n", filename);
		return -1;
	}

	return 0;
}

int elf_read_library(struct task *task, struct libref *libref, const char *filename, GElf_Addr bias)
{
	struct mt_elf mte = { };
	int ret;

	libref_set_filename(libref, filename);

	if (elf_read(&mte, task, filename) == -1)
		return -1;

	mte.bias = bias;
	mte.entry_addr = mte.ehdr.e_entry - mte.vstart + bias;

	ret = elf_lib_init(&mte, task, libref);

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

struct libref *elf_read_main_binary(struct task *task, int was_attached)
{
	char fname[PATH_MAX];
	int ret;
	char *filename;
	struct mt_elf mte = { };
	unsigned long entry;
	unsigned long base;
	struct libref *libref;

	filename = pid2name(task->pid);
	if (!filename)
		return NULL;

	libref = libref_new(LIBTYPE_MAIN);
	if (libref == NULL)
		goto fail1;

	ret = readlink(filename, fname, sizeof(fname) - 1);
	if (ret == -1)
		goto fail2;

	fname[ret] = 0;

	free(filename);

	libref_set_filename(libref, fname);

	if (elf_read(&mte, task, fname) == -1)
		goto fail3;

	task->is_64bit = is_64bit(&mte);

	if (process_get_entry(task, &entry, &base) < 0) {
		fprintf(stderr, "Couldn't find process entry of %s\n", filename);
		goto fail3;
	}

	mte.bias = entry - mte.ehdr.e_entry - mte.vstart;
	mte.entry_addr = entry;

	if (elf_lib_init(&mte, task, libref))
		goto fail3;

	close_elf(&mte);

	report_attach(task, was_attached);

	library_add(task, libref);

	if (!mte.interp)
		return libref;

	struct mt_elf mte_ld = { };

	if (copy_str_from_proc(task, ARCH_ADDR_T(mte.bias + mte.interp - mte.vstart), fname, sizeof(fname)) == -1) {
		fprintf(stderr, "fatal error: cannot get loader name for pid=%d\n", task->pid);
		abort();
	}

	if (!elf_read(&mte_ld, task, fname)) {
		struct libref *libref;

		libref = libref_new(LIBTYPE_LOADER);
		if (libref == NULL)
			goto fail4;

		libref_set_filename(libref, fname);

		mte_ld.bias = base;
		mte_ld.entry_addr = base + mte_ld.ehdr.e_entry  - mte.vstart;

		ret = elf_lib_init(&mte_ld, task, libref);
		if (!ret) {
			library_add(task, libref);

			if (linkmap_init(task, ARCH_ADDR_T(mte.bias + mte.dyn - mte.vstart))) {
				arch_addr_t addr = find_solib_break(&mte_ld);
				if (!addr)
					addr = ARCH_ADDR_T(entry);

				struct entry_breakpoint *entry_bp = (void *)breakpoint_new_ext(task, addr, NULL, 0, sizeof(*entry_bp) - sizeof(entry_bp->breakpoint));
				if (!entry_bp)
					fprintf(stderr,
						"Couldn't initialize entry breakpoint for PID %d.\n"
						"Tracing events may be missed.\n",
						task->pid
					);
				else {
					entry_bp->breakpoint.on_hit = entry_breakpoint_on_hit;
					entry_bp->breakpoint.locked = 1;
					entry_bp->dyn_addr = ARCH_ADDR_T(mte.bias + mte.dyn - mte.vstart);

					breakpoint_enable(task, &entry_bp->breakpoint);
				}
			}
		}
		else {
			fprintf(stderr,
				"Couldn't read dynamic loader `%s` for PID %d.\n"
				"Tracing events may be missed.\n",
				fname,
				task->pid
			);
		}
fail4:
		close_elf(&mte_ld);
	}
	else {
		fprintf(stderr,
			"Couldn't open dynamic loader `%s` for PID %d.\n"
			"Tracing events may be missed.\n",
			fname,
			task->pid
		);
	}

	return libref;
fail3:
	close_elf(&mte);
fail2:
	libref_delete(libref);
fail1:
	free(filename);
	return libref;
}

int mte_cmp_machine(struct mt_elf *mte, Elf64_Half type)
{
	return mte->ehdr.e_machine == type;
}

