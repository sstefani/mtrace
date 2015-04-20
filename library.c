/*
 * This file is part of mtrace.
 * Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
 *  This file is based on the ltrace source
 *   Copyright (C) 2011,2012 Petr Machata, Red Hat Inc.
 *   Copyright (C) 2001,2009 Juan Cespedes
 *   Copyright (C) 2006 Ian Wienand
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>

#include "backend.h"
#include "breakpoint.h"
#include "debug.h"
#include "dict.h"
#include "library.h"
#include "report.h"
#include "server.h"
#include "task.h"

struct library_symbol *library_symbol_new(struct library *lib, arch_addr_t addr, const struct function *func)
{
	struct library_symbol *libsym = malloc(sizeof(*libsym));

	if (!libsym)
		return NULL;

	INIT_LIST_HEAD(&libsym->list);
	libsym->lib = NULL;
	libsym->func = func;
	libsym->addr = addr;

	list_add_tail(&libsym->list, &lib->sym_list);

	return libsym;
}

static void library_symbol_destroy(struct task *task, struct library_symbol *libsym)
{
	struct breakpoint *bp = breakpoint_find(task, libsym->addr);

	if (bp)
		breakpoint_delete(task, bp);

	list_del(&libsym->list);
	free(libsym);
}

static struct library_symbol *library_symbol_clone(struct library *lib, struct library_symbol *libsym)
{
	struct library_symbol *retp = library_symbol_new(lib, libsym->addr, libsym->func);
	if (!retp)
		return NULL;

	return retp;
}

struct library *library_new(void)
{
	struct library *lib = malloc(sizeof(*lib));

	if (lib == NULL)
		return NULL;

	memset(lib, 0, sizeof(*lib));

	INIT_LIST_HEAD(&lib->list);
	INIT_LIST_HEAD(&lib->sym_list);

	return lib;
}

void library_destroy(struct task *task, struct library *lib)
{
	if (lib == NULL)
		return;

	struct list_head *it, *next;

	list_for_each_safe(it, next, &lib->sym_list) {
		struct library_symbol *sym = container_of(it, struct library_symbol, list);

		library_symbol_destroy(task, sym);
	}

	list_del(&lib->list);

	if (lib->image_addr)
		munmap(lib->image_addr, lib->load_size);

	free(lib);
}

void library_set_filename(struct library *lib, const char *new_name)
{
	free((void *)lib->filename);
	lib->filename = new_name ? strdup(new_name) : NULL;
}

static struct library *library_clone(struct task *clone, struct library *lib)
{
	struct list_head *it;
	struct library *retp = library_new();

	if (!retp)
		return NULL;

	library_set_filename(retp, lib->filename);

	retp->key = lib->key;

	/* Clone symbols.  */
	list_for_each(it, &lib->sym_list) {
		if (!library_symbol_clone(retp, container_of(it, struct library_symbol, list)))
			goto fail;
	}

	return retp;
fail:
	/* Release what we managed to allocate.  */
	library_destroy(clone, retp);
	return NULL;
}

static void library_each_symbol(struct library *lib, void (*cb)(struct library_symbol *, void *), void *data)
{
	struct list_head *it, *next;

	list_for_each_safe(it, next, &lib->sym_list) {
		struct library_symbol *sym = container_of(it, struct library_symbol, list);

		(*cb) (sym, data);
	}
}

struct library_symbol *library_find_symbol(struct library *lib, arch_addr_t addr)
{
	struct list_head *it;

	list_for_each(it, &lib->sym_list) {
		struct library_symbol *sym = container_of(it, struct library_symbol, list);

		if (sym->addr == addr)
			return sym;
	}
	return NULL;
}

struct library_symbol *find_symbol(struct task *leader, arch_addr_t addr)
{
	/* Clone symbols first so that we can clone and relink breakpoints. */
	struct list_head *it;

	list_for_each(it, &leader->libraries_list) {
		struct library *lib = container_of(it, struct library, list);
		struct library_symbol *libsym = library_find_symbol(lib, addr);

		if (libsym)
			return libsym;
	}
	return NULL;
}

struct library *library_find_with_key(struct list_head *list, arch_addr_t key)
{
	struct list_head *it;

	list_for_each(it, list) {
		struct library *lib = container_of(it, struct library, list);

		if (lib->key == key)
			return lib;
	}
	return NULL;
}

void library_delete_list(struct task *leader, struct list_head *list)
{
	struct list_head *it, *next;

	list_for_each_safe(it, next, list) {
		struct library *lib = container_of(it, struct library, list);

		debug(DEBUG_FUNCTION, "%s@%#lx", lib->filename, lib->base);

		library_destroy(leader, lib);
	}
}

static void cb_breakpoint_for_symbol(struct library_symbol *libsym, void *data)
{
	struct task *task = data;
	arch_addr_t addr = libsym->addr;
	struct breakpoint *bp = breakpoint_find(task, addr);

	if (bp) {
		assert(bp->libsym == NULL);

		bp->libsym = libsym;
		return;
	}
	bp = breakpoint_new(task, addr, libsym, libsym->func->hw_bp_min <= HW_BREAKPOINTS ? HW_BP : SW_BP);
	if (!bp)
		fprintf(stderr, "Couldn't insert breakpoint for %s to %d: %s.", libsym->func->name, task->pid, strerror(errno));

	if (server_connected())
		breakpoint_enable(task, bp);
}

void library_add(struct task *leader, struct library *lib)
{
	assert(leader->leader == leader);

	debug(DEBUG_PROCESS, "%s@%#lx to pid=%d", lib->filename, lib->base, leader->pid);

	/* Insert breakpoints for all active symbols.  */
	library_each_symbol(lib, cb_breakpoint_for_symbol, leader);

	list_add_tail(&lib->list, &leader->libraries_list);

	report_add_map(leader, lib);
}

void cb_remove_breakpoint_for_symbol(struct library_symbol *libsym, void *data)
{
	struct task *task = data;
	arch_addr_t addr = libsym->addr;
	struct breakpoint *bp = breakpoint_find(task, addr);

	if (bp)
		breakpoint_delete(task, bp);
}

void library_remove(struct task *leader, struct library *lib)
{
	debug(DEBUG_PROCESS, "%s@%#lx to pid=%d", lib->filename, lib->base, leader->pid);

	library_each_symbol(lib, cb_remove_breakpoint_for_symbol, leader);

	list_del(&lib->list);

	report_del_map(leader, lib);
}

void library_clear_all(struct task *leader)
{
	library_delete_list(leader, &leader->libraries_list);
}

int library_clone_all(struct task *clone, struct task *leader)
{
	struct list_head *it;

	list_for_each(it, &leader->libraries_list) {
		struct library *lib = container_of(it, struct library, list);
		struct library *nlibp = library_clone(clone, lib);

		if (!nlibp)
			return -1;

		list_add_tail(&nlibp->list, &clone->libraries_list);
	}
	return 0;
}

void library_setup(struct task *leader)
{
	INIT_LIST_HEAD(&leader->libraries_list);
}

const char *library_execname(struct task *leader)
{
	if (list_empty(&leader->libraries_list))
		return NULL;

	return container_of(leader->libraries_list.next, struct library, list)->filename;
}

