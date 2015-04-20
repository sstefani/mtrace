/*
 * This file is part of mtrace.
 * Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
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

#define _GNU_SOURCE

#include <execinfo.h>
#include <link.h>
#include <stdio.h>

#include "binfile.h"
#include "process.h"

/* These variables are used to pass information between
   translate_addresses and find_address_in_section.  */
struct sym_info {
	bfd_vma pc;
	asymbol **syms;
	const char *filename;
	const char *functionname;
	unsigned int line;
	bfd_boolean found;
};

static long slurp_symtab(struct bin_file *binfile)
{
	long storage;
	long symcount;
	bfd_boolean dynamic = FALSE;

	if ((bfd_get_file_flags(binfile->abfd) & HAS_SYMS) == 0)
		return 0;

	storage = bfd_get_symtab_upper_bound(binfile->abfd);
	if (storage == 0) {
		storage = bfd_get_dynamic_symtab_upper_bound(binfile->abfd);
		dynamic = TRUE;
	}

	if (storage < 0)
		return 0;

	binfile->syms = (asymbol **)malloc(storage);
	if (dynamic)
		symcount = bfd_canonicalize_dynamic_symtab(binfile->abfd, binfile->syms);
	else
		symcount = bfd_canonicalize_symtab(binfile->abfd, binfile->syms);
	if (symcount < 0)
		return 0;

	/* If there are no symbols left after canonicalization and
		 we have not tried the dynamic symbols then give them a go.	*/
	if (symcount == 0 && ! dynamic && (storage = bfd_get_dynamic_symtab_upper_bound(binfile->abfd)) > 0) {
		free(binfile->syms);
		binfile->syms = malloc(storage);
		symcount = bfd_canonicalize_dynamic_symtab(binfile->abfd, binfile->syms);
	}
	return symcount;
}

static void find_address_in_section(bfd *abfd, asection *section, void *data __attribute__ ((__unused__)))
{
	bfd_vma vma;
	bfd_size_type size;
	struct sym_info *psi = (struct sym_info *) data;

	if (psi->found)
		return;

	if ((bfd_get_section_flags(abfd, section) & SEC_ALLOC) == 0)
		return;

	vma = bfd_get_section_vma(abfd, section);
	if (psi->pc < vma)
		return;
	size = bfd_section_size(abfd, section);
	if (psi->pc >= vma + size)
		return;

	psi->found = bfd_find_nearest_line(abfd, section, psi->syms, psi->pc - vma, &psi->filename, &psi->functionname, &psi->line);
}

char *bin_file_lookup(struct bin_file *binfile, bfd_vma addr, unsigned long off)
{
	struct sym_info si = { 0 };
	char *ret_buf = NULL;

	if (!binfile)
		return NULL;

	if (!binfile->abfd)
		return NULL;

	if (!binfile->syms)
		return NULL;

	si.pc = (binfile->abfd->flags & EXEC_P) ? addr : addr - off;
	si.syms = binfile->syms;
	si.found = FALSE;
	si.line = 0;

	bfd_map_over_sections(binfile->abfd, find_address_in_section, &si);

	if (!si.found) {
		if (asprintf(&ret_buf, "%s", bfd_get_filename(binfile->abfd)) == -1)
			ret_buf = NULL;
	} else {
		const char *name;

		do {
			char *alloc = NULL;

			name = si.functionname;
			if (name == NULL || *name == '\0') {
				if (asprintf(&alloc, "[0x%lx]", (unsigned long)addr) == -1)
					name = "?";
				else
					name = alloc;
			}
			else {
				alloc = bfd_demangle(binfile->abfd, name, 27);
				if (alloc != NULL)
					name = alloc;
			}

			if (ret_buf)
				free(ret_buf);

			if (si.line) {
				if (asprintf(&ret_buf, "%s:%u %s", si.filename ? si.filename : bfd_get_filename(binfile->abfd), si.line, name) == -1)
					ret_buf = NULL;
			}
			else {
				if (asprintf(&ret_buf, "%s %s", si.filename ? si.filename : bfd_get_filename(binfile->abfd), name) == -1)
					ret_buf = NULL;
			}

			if (alloc)
				free(alloc);

			si.found = bfd_find_inliner_info(binfile->abfd, &si.filename, &si.functionname, &si.line);
		} while (si.found);
	}

	return ret_buf;
}

struct bin_file *bin_file_new(const char *filename)
{
	bfd *abfd;
	char **matching;
	struct bin_file *binfile;

	if (!filename)
		return NULL;

	binfile = malloc(sizeof(struct bin_file));
	if (!binfile)
		return NULL;

	abfd = bfd_openr(filename, NULL);
	if (!abfd)
		goto error;

	/* Decompress sections.  */
//	abfd->flags |= BFD_DECOMPRESS;

	if (bfd_check_format(abfd, bfd_archive))
		goto error;

	if (!bfd_check_format_matches(abfd, bfd_object, &matching))
		goto error;

	binfile->abfd = abfd;

	if (slurp_symtab(binfile) <= 0)
		goto error;

	binfile->refcnt = 1;

	return binfile;
error:
	if (abfd)
		bfd_close(abfd);
	free(binfile);

	return NULL;
}

struct bin_file *bin_file_clone(struct bin_file *binfile)
{
	if (!binfile)
		return NULL;

	binfile->refcnt++;

	return binfile;
}

void bin_file_free(struct bin_file *binfile)
{
	if (!binfile)
		return;

	if (--binfile->refcnt > 0)
		return;

	if (binfile->syms)
		free(binfile->syms);

	if (binfile->abfd)
		bfd_close(binfile->abfd);
}
