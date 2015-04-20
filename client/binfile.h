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

#ifndef _INC_CLIENT_BINFILE_H
#define _INC_CLIENT_BINFILE_H

#include "bfdinc.h"

struct bin_file {
	bfd *abfd;
	asymbol **syms;
	unsigned int refcnt;
};

struct bin_file *bin_file_new(const char *filename);
struct bin_file *bin_file_clone(struct bin_file *binfile);
void bin_file_free(struct bin_file *binfile);
char *bin_file_lookup(struct bin_file *binfile, bfd_vma addr, unsigned long off);

#endif
