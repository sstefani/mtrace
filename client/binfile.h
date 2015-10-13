/*
 * This file is part of mtrace.
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

#ifndef _INC_CLIENT_BINFILE_H
#define _INC_CLIENT_BINFILE_H

#include "bfdinc.h"
#include "list.h"
#include "rbtree.h"

struct rb_sym {
	struct rb_node node;
	bfd_vma addr;
	char *sym;
	struct bin_file *binfile;
	unsigned long refcnt;
};

struct bin_file {
	struct list_head list;
	bfd *abfd;
	asymbol **syms;
	struct rb_root sym_table;
	unsigned long refcnt;
	char *filename;
};

struct bin_file *bin_file_open(const char *filename);
void bin_file_put(struct bin_file *binfile);
void bin_file_get(struct bin_file *binfile);
struct rb_sym *bin_file_lookup(struct bin_file *binfile, bfd_vma addr, unsigned long off, const char *filename);
void bin_file_sym_get(struct rb_sym *sym);
void bin_file_sym_put(struct rb_sym *sym);

#endif
