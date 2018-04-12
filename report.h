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

#ifndef _INC_REPORT_H
#define _INC_REPORT_H

#include <unistd.h>

#include "forward.h"

struct function {
	/* symbol name */
	const char *demangled_name;
	/* symbol name */
	const char *name;
	/* level for aliased symbol */
	unsigned int level;
	/* report when function is entered */
	void (*report_in)(struct task *task, struct library_symbol *libsym);
	/* report when function is exited */
	void (*report_out)(struct task *task, struct library_symbol *libsym);
};

const struct function *flist_matches_symbol(const char *sym_name);

int report_add_map(struct task *task, struct library *lib);
int report_del_map(struct task *task, struct library *lib);
int report_info(int do_trace);
int report_scan(pid_t pid, const void *data, unsigned int data_len);
int report_attach(struct task *task, int was_attached);
int report_fork(struct task *task, struct task *ptask);
int report_exit(struct task *task);
int report_about_exit(struct task *task);
int report_nofollow(struct task *task);
int report_disconnect(void);
int report_processes(void);
int report_detach(struct task *task);

#endif

