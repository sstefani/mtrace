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

#ifndef _INC_BACKTRACE_H
#define _INC_BACKTRACE_H

#include "task.h"

/* init backtrace for given leader task */
int backtrace_init(struct task *task);

/* destroy backtrace for given leader task */
void backtrace_destroy(struct task *task);

/* start backtrace for given task */
int backtrace_init_unwind(struct task *task);

/* get backtrace IP address for given task */
unsigned long backtrace_get_ip(struct task *task);

/* step to next backtrace given task */
int backtrace_step(struct task *task);

/* get backtrace location type of given task */
int backtrace_location_type(struct task *task);

#endif

