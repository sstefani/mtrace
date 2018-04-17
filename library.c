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
#include "options.h"
#include "report.h"
#include "server.h"
#include "task.h"

struct libref *libref_new(unsigned int type)
{
	struct libref *libref = malloc(sizeof(*libref));

	if (!libref)
		return NULL;

	memset(libref, 0, sizeof(*libref));

	libref->refcnt = 0;
	libref->type = type;

	INIT_LIST_HEAD(&libref->sym_list);

	return libref;
}


void libref_delete(struct libref *libref)
{
	struct list_head *it, *next;

	list_for_each_safe(it, next, &libref->sym_list) {
		struct library_symbol *sym = container_of(it, struct library_symbol, list);

		list_del(&sym->list);
		free(sym);
	}

	if (libref->mmap_addr)
		munmap(libref->mmap_addr, libref->txt_size);

	free((void *)libref->filename);
	free(libref);
}

static void libref_put(struct libref *libref)
{
	assert(libref->refcnt != 0);

	if (!--libref->refcnt)
		libref_delete(libref);
}

static struct libref *libref_get(struct libref *libref)
{
	assert(libref);

	++libref->refcnt;

	return libref;
}

void libref_set_filename(struct libref *libref, const char *new_name)
{
	free((void *)libref->filename);
	libref->filename = new_name ? strdup(new_name) : NULL;
}

struct library_symbol *library_symbol_new(struct libref *libref, arch_addr_t addr, const struct function *func)
{
	struct library_symbol *libsym = malloc(sizeof(*libsym));

	if (!libsym)
		return NULL;

	libsym->libref = libref;
	libsym->func = func;
	libsym->addr = addr;

	list_add_tail(&libsym->list, &libref->sym_list);

	return libsym;
}

static void library_delete(struct task *task, struct library *lib)
{
	if (lib == NULL)
		return;

	struct list_head *it, *next;
	struct libref *libref = lib->libref;
	struct task *leader = task->leader;

	list_for_each_safe(it, next, &libref->sym_list) {
		struct breakpoint *bp = breakpoint_find(leader, container_of(it, struct library_symbol, list)->addr);

		if (bp)
			breakpoint_delete(leader, bp);
	}

	list_del(&lib->list);
	rb_erase(&lib->rb_node, &leader->libraries_tree);

	free(lib);

	libref_put(libref);
}

struct library_symbol *library_find_symbol(struct libref *libref, arch_addr_t addr)
{
	struct list_head *it;

	list_for_each(it, &libref->sym_list) {
		struct library_symbol *sym = container_of(it, struct library_symbol, list);

		if (sym->addr == addr)
			return sym;
	}
	return NULL;
}

struct library *library_find_by_dyn(struct list_head *list, arch_addr_t dyn)
{
	struct list_head *it;

	list_for_each(it, list) {
		struct library *lib = container_of(it, struct library, list);

		if (lib->libref->dyn == dyn)
			return lib;
	}
	return NULL;
}

void library_delete_list(struct task *leader, struct list_head *list)
{
	struct list_head *it, *next;

	list_for_each_safe(it, next, list) {
		struct library *lib = container_of(it, struct library, list);
		struct libref *libref = lib->libref;

		debug(DEBUG_FUNCTION, "%s@%#lx pid=%d ", libref->filename, libref->dyn, leader->pid);

		if (unlikely(options.verbose > 1))
			fprintf(stderr, "+++ library del pid=%d %s@%#lx %#lx-%#lx\n", leader->pid, libref->filename, libref->dyn, libref->txt_vaddr, libref->txt_vaddr + libref->txt_size);

		library_delete(leader, lib);
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
	bp = breakpoint_new(task, addr, libsym, BP_AUTO);
	if (!bp)
		fprintf(stderr, "Couldn't insert breakpoint for %s to %d: %s", libsym->func->name, task->pid, strerror(errno));

	if (server_connected())
		breakpoint_enable(task, bp);
}

static void library_each_symbol(struct libref *libref, void (*cb)(struct library_symbol *, void *), void *data)
{
	struct list_head *it, *next;

	list_for_each_safe(it, next, &libref->sym_list) {
		struct library_symbol *sym = container_of(it, struct library_symbol, list);

		(*cb) (sym, data);
	}
}

struct libref *addr2libref(struct task *leader, arch_addr_t addr)
{
	struct rb_node **new = &(leader->libraries_tree.rb_node);

	/* Figure out where to put new node */
	while (*new) {
		struct libref *this = container_of(*new, struct library, rb_node)->libref;

		if (addr >= this->txt_vaddr && addr < this->txt_vaddr + this->txt_size)
			return this;

		if (this->txt_vaddr < addr)
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
	}

	return NULL;
}

static void insert_lib(struct task *leader, struct library *lib)
{
	struct rb_node **new = &(leader->libraries_tree.rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct library *this = container_of(*new, struct library, rb_node);

		parent = *new;

		if (this->libref->txt_vaddr < lib->libref->txt_vaddr)
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&lib->rb_node, parent, new);
	rb_insert_color(&lib->rb_node, &leader->libraries_tree);
}

static struct library *_library_add(struct task *leader, struct libref *libref)
{
	debug(DEBUG_PROCESS, "%s@%#lx to pid=%d", libref->filename, libref->dyn, leader->pid);

	assert(leader->leader == leader);

	struct library *lib = malloc(sizeof(*lib));

	memset(lib, 0, sizeof(*lib));

	lib->libref = libref_get(libref);

	list_add_tail(&lib->list, &leader->libraries_list);

	insert_lib(leader, lib);

	if (unlikely(options.verbose > 1))
		fprintf(stderr, "+++ library add pid=%d %s@%#lx %#lx-%#lx\n", leader->pid, libref->filename, libref->dyn, libref->txt_vaddr, libref->txt_vaddr + libref->txt_size);

	return lib;
}

struct library *library_add(struct task *leader, struct libref *libref)
{
	struct library *lib = _library_add(leader, libref);

	/* Insert breakpoints for all active symbols.  */
	library_each_symbol(libref, cb_breakpoint_for_symbol, leader);

	report_add_map(leader, lib);

	return lib;
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

		_library_add(clone, lib->libref);
	}
	return 0;
}

void library_setup(struct task *leader)
{
	INIT_LIST_HEAD(&leader->libraries_list);
	leader->libraries_tree = RB_ROOT;
}

const char *library_execname(struct task *leader)
{
	if (list_empty(&leader->libraries_list))
		return NULL;

	return container_of(leader->libraries_list.next, struct library, list)->libref->filename;
}

