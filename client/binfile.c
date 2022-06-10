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

#define _GNU_SOURCE

#include <execinfo.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <libiberty/demangle.h>

#include <bfd.h>

/* try to detect libfd version and set up wrapper accprdingly. */
#ifdef  bfd_get_section_flags
// 2.31 (and possibly earlier) has bfd_get_section_flags
#define bfd_section_size_wrapper(_ptr, _section) bfd_section_size(_ptr, _section)
#define bfd_section_vma_wrapper(_ptr, _section) bfd_section_vma(_ptr, _section)
#else
// works for 2.34
#define bfd_get_section_flags(_unused, _section) bfd_section_flags(_section)
#define bfd_section_size_wrapper(_unused, _section) bfd_section_size(_section)
#define bfd_section_vma_wrapper(_unused, _section) bfd_section_vma(_section)
#endif

#include "binfile.h"
#include "process.h"

static LIST_HEAD(list_of_binfiles);

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
	if (!storage) {
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

	vma = bfd_section_vma_wrapper(abfd, section);
	if (psi->pc < vma)
		return;
	size = bfd_section_size_wrapper(abfd, section);
	if (psi->pc >= vma + size)
		return;

	psi->found = bfd_find_nearest_line(abfd, section, psi->syms, psi->pc - vma, &psi->filename, &psi->functionname, &psi->line);
}

struct rb_sym *bin_file_lookup(struct bin_file *binfile, bfd_vma addr, unsigned long off)
{
	struct sym_info si = { 0 };
	char *sym_buf = NULL;
	struct rb_root *root = &binfile->sym_table;
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct rb_sym *this;
	unsigned int si_info = 0;

	if (!binfile)
		return NULL;

	/* Figure out where to put new node */
	while (*new) {
		this = container_of(*new, struct rb_sym, node);

		parent = *new;

		if (addr < this->addr)
			new = &((*new)->rb_left);
		else
		if (addr > this->addr)
			new = &((*new)->rb_right);
		else {
			bin_file_sym_get(this);

			return this;
		}
	}

	si.pc = (binfile->abfd->flags & EXEC_P) ? addr : addr - off;
	si.syms = binfile->syms;
	si.found = FALSE;
	si.line = 0;

	bfd_map_over_sections(binfile->abfd, find_address_in_section, &si);

	if (si.found) {
		const char *name;
		char *alloc = NULL;

		if (sym_buf)
			free(sym_buf);

		name = si.functionname;

		if (!name || !*name)
			name = "?";
		else {
			alloc = bfd_demangle(binfile->abfd, name, DMGL_ANSI | DMGL_PARAMS | DMGL_RET_DROP | DMGL_AUTO);
			if (alloc)
				name = alloc;
		}

		if (si.filename) {
			if (si.line) {
				if (asprintf(&sym_buf, "%s:%u %s", si.filename, si.line, name) == -1)
					sym_buf = NULL;
				else
					si_info = 1;
			}
			else {
				if (asprintf(&sym_buf, "%s %s", si.filename, name) == -1)
					sym_buf = NULL;
				else
					si_info = 1;
			}
		}
		else
			sym_buf = strdup(name);

		if (alloc)
			free(alloc);
	}

	this = malloc(sizeof(*this));
	if (!this)
		return NULL;

	this->addr = addr;
	this->sym = sym_buf;
	this->refcnt = 1;
	this->binfile = binfile;
	this->si_info = si_info;

	++binfile->refcnt;

	/* Add new node and rebalance tree. */
	rb_link_node(&this->node, parent, new);
	rb_insert_color(&this->node, root);

	return this;
}

struct bin_file *bin_file_open(const char *filename, const char *mapname)
{
	char **matching;
	struct bin_file *binfile;
	struct list_head *it;

	if (!filename)
		return NULL;

	list_for_each(it, &list_of_binfiles) {
		binfile = container_of(it, struct bin_file, list);

		if (!strcmp(filename, binfile->filename)) {
			bin_file_get(binfile);
			return binfile;
		}
	}

	binfile = malloc(sizeof(struct bin_file));
	if (!binfile)
		return NULL;

	binfile->filename = strdup(filename);
	binfile->mapname = strdup(mapname);
	binfile->refcnt = 1;
	binfile->sym_table = RB_ROOT;
	binfile->abfd = bfd_openr(binfile->filename, NULL);

	if (!binfile->abfd)
		goto error;

	if (bfd_check_format(binfile->abfd, bfd_archive))
		goto error;

	if (!bfd_check_format_matches(binfile->abfd, bfd_object, &matching))
		goto error;

	if (slurp_symtab(binfile) <= 0)
		goto error;

	list_add_tail(&binfile->list, &list_of_binfiles);

	return binfile;
error:
	if (binfile->abfd)
		bfd_close(binfile->abfd);
	free(binfile->filename);
	free(binfile->mapname);
	free(binfile);

	return NULL;
}

void bin_file_get(struct bin_file *binfile)
{
	++binfile->refcnt;
}

void bin_file_put(struct bin_file *binfile)
{
	if (!binfile)
		return;

	if (!--binfile->refcnt) {
		list_del(&binfile->list);

		if (binfile->syms)
			free(binfile->syms);

		if (binfile->abfd)
			bfd_close(binfile->abfd);

		free(binfile->filename);
		free(binfile->mapname);
		free(binfile);
	}
}

void bin_file_sym_get(struct rb_sym *sym)
{
	struct bin_file *binfile = sym->binfile;

	++sym->refcnt;
	++binfile->refcnt;
}

void bin_file_sym_put(struct rb_sym *sym)
{
	struct bin_file *binfile = sym->binfile;

	if (!--sym->refcnt) {
		free(sym->sym);

		if (binfile)
			rb_erase(&sym->node, &binfile->sym_table);
		free(sym);
	}
	bin_file_put(binfile);
}

