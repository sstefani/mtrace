/*
 * This file is part of mtrace-ng.
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

#ifndef _INC_LIBRARY_H
#define _INC_LIBRARY_H

#include <stdint.h>

#include "forward.h"
#include "sysdep.h"
#include "list.h"
#include "mtelf.h"

#define LIBTYPE_LIB	0
#define LIBTYPE_MAIN	1
#define LIBTYPE_LOADER	2

struct library_symbol {
	struct list_head list;
	struct libref *libref;
	const struct function *func;
	arch_addr_t addr;
};

struct libref {
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
	unsigned int type;

#ifdef __arm__
	void *exidx_data;
	unsigned long exidx_len;
#endif

	unsigned int refcnt;

	/* Symbols associated with the library.  This includes a
	 * symbols that don't have a breakpoint attached (yet).  */
	struct list_head sym_list;
};

struct library {
	/* link list of libraries associated with the task */
	struct list_head list;

	/* pointer to the real library refernce */
	struct libref *libref;
};

/* create a new symbol */
struct library_symbol *library_symbol_new(struct libref *libref, arch_addr_t addr, const struct function *func);

/* Delete library. Symbols are destroyed and freed. */
void library_delete(struct task *leader, struct library *lib);

/* Add a library to the list of the thread leader libraries.  */
struct library *library_add(struct task *leader, struct libref *libref);

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
struct library_symbol *library_find_symbol(struct libref *libref, arch_addr_t addr);

/* find a library with a given key */
struct library *library_find_with_key(struct list_head *list, arch_addr_t key);

/* create a library reference. */
struct libref *libref_new(unsigned int type);

/* delete a library reference. */
void libref_delete(struct libref *libref);

/* Set library filename.  Frees the old name if necessary.  */
void libref_set_filename(struct libref *libref, const char *new_name);

#endif

