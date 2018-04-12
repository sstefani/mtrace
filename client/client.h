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

#ifndef _INC_CLIENT_CLIENT_H
#define _INC_CLIENT_CLIENT_H

#include "memtrace.h"

struct process;

struct process *client_first_process(void);
struct process *client_find_process(unsigned int pid);
void client_iterate_processes(int (*func)(struct process *process));
void client_show_info(void);
int client_set_depth(int depth);
void client_request_info(void);
int client_wait_op(enum mt_operation op);
void client_close(void);
int client_send_msg(struct process *process, enum mt_operation op, void *payload, unsigned int payload_len);
int client_connected(void);
int client_start(void);
int client_start_pair(int handle);
int client_stop(void);
int client_logfile(void);

#endif

