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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "client.h"
#include "common.h"
#include "job.h"
#include "process.h"

void leaks_scan(struct process *process, int mode)
{
	process_leaks_scan(process, mode);

	client_wait_op(MT_SCAN);
}

void dump_stacks(struct process *process, void (*dump)(struct process *process, const char *outfile, int lflag), const char *outfile, int lflag)
{
	if (!process->n_allocations)
		return;

	dump(process, outfile, lflag);
}

