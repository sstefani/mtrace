/*
 * This file is part of mtrace.
 * Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
 *
 * This work was sponsored by Rohde & Schwarz GmbH & Co. KG, Munich.
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

#ifndef _INC_EVENT_H
#define _INC_EVENT_H

#include "forward.h"
#include "list.h"

enum event_type {
	EVENT_NONE = 0,
	EVENT_SIGNAL,
	EVENT_ABOUT_EXIT,
	EVENT_EXIT,
	EVENT_EXIT_SIGNAL,
	EVENT_FORK,
	EVENT_CLONE,
	EVENT_VFORK,
	EVENT_EXEC,
	EVENT_BREAKPOINT
};

struct event {
	struct list_head list;
	enum event_type type;
	union {
		int ret_val;			/* EVENT_EXIT */
		int signum;			/* EVENT_SIGNAL, EVENT_EXIT_SIGNAL */
		struct breakpoint *breakpoint;	/* EVENT_BREAKPOINT */
		int newpid;			/* EVENT_CLONE, EVENT_FORK, EVENT_VFORK */
	} e_un;
};

void init_event(struct task *task);
void remove_event(struct task *task);
struct task *next_event(void);
void wait_for_event(struct task *task);
void queue_event(struct task *task);
int handle_event(void);

#endif

