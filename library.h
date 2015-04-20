/*
 * This file is part of mtrace.
 * Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
 *  This file is based on the ltrace source
 *   Copyright (C) 2012 Petr Machata, Red Hat Inc.
 *   Copyright (C) 2006 Paul Gilliam, IBM Corporation
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

#ifndef _INC_LIBRARY_H
#define _INC_LIBRARY_H

#include <stdint.h>

#include "forward.h"
#include "sysdep.h"
#include "list.h"
#include "mtelf.h"

struct library_symbol {
	struct list_head list;
	struct library *lib;
	const struct function *func;
	arch_addr_t addr;
};

struct library_symbol *library_symbol_new(struct library *lib, arch_addr_t addr, const struct function *func);

struct library {
	struct list_head list;
	/* Symbols associated with the library.  This includes a
	 * symbols that don't have a breakpoint attached (yet).  */
	struct list_head sym_list;

	/* Unique key. Two library objects are considered equal, if
	 * they have the same key.  */
	arch_addr_t key;

	/* Address where the library is mapped.  */
	arch_addr_t base;

	/* Absolute address of the entry point.  Useful for main
	 * binary, though I suppose the value might be useful for the
	 * dynamic linker, too (in case we ever want to do early
	 * process tracing).  */
	arch_addr_t entry;

	const char *filename;

	/* executable segment */
	unsigned long load_offset;
	unsigned long load_addr;
	unsigned long load_size;

	/* mapped image */
	void *image_addr;

	/* global-pointer */
	arch_addr_t gp;
	unsigned long seg_offset;
	void *table_data;
	unsigned long table_len;
#ifdef __arm__
	void *exidx_data;
	unsigned long exidx_len;
#endif
};

/* Init LIB.  */
struct library *library_new(void);

/* Destroy library.  Doesn't free LIB itself.  Symbols are destroyed
 * and freed.  */
void library_destroy(struct task *leader, struct library *lib);

/* Set library filename.  Frees the old name if necessary.  */
void library_set_filename(struct library *lib, const char *new_name);

/* Add a library to the list of the thread leader libraries.  */
void library_add(struct task *leader, struct library *lib);

/* delete a given list of libraries */
void library_delete_list(struct task *leader, struct list_head *list);

/* delete all libraries of a given leader */
void library_clear_all(struct task *leader);

/* cline all libraries of a given leader to a new task leader*/
int library_clone_all(struct task *clone, struct task *leader);

/* setup library list of a given leader */
void library_setup(struct task *leader);

/* get the pathname of the executable */
const char *library_execname(struct task *leader);

/* Iterate through list of symbols of library. */
struct library_symbol *library_find_symbol(struct library *lib, arch_addr_t addr);

/* find a library with a given key */
struct library *library_find_with_key(struct list_head *list, arch_addr_t key);

/* Iterate through list all symbols of leader task. */
struct library_symbol *find_symbol(struct task *leader, arch_addr_t addr);

#endif

