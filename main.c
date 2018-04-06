/*
 * This file is part of mtrace-ng.
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

#include "config.h"

#define _GNU_SOURCE

#include <sys/param.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "backend.h"
#include "breakpoint.h"
#include "common.h"
#ifndef DISABLE_CLIENT
#include "client.h"
#endif
#include "debug.h"
#include "options.h"
#include "library.h"
#include "main.h"
#include "mtelf.h"
#include "mtrace.h"
#include "server.h"
#include "task.h"
#include "trace.h"

struct mt_timer stop_time;
struct mt_timer sw_bp_time;
struct mt_timer hw_bp_time;
struct mt_timer backtrace_time;
struct mt_timer reorder_time;
struct mt_timer report_in_time;
struct mt_timer report_out_time;
struct mt_timer skip_bp_time;

pid_t mtrace_pid;

static int do_exit;

void mtrace_request_exit(void)
{
	if (do_exit)
		return;

	if (unlikely(options.verbose))
		fprintf(stderr, "+++ request exit\n");

	do_exit = 1;
	wait_event_wakeup();
}

static void detach_process(struct task *leader)
{
	if (!leader)
		return;

	pid_t pid = leader->pid;

	report_detach(leader);

	while(server_handle_command() != -1) {
		struct task *task = pid2task(pid);

		if (!task)
			break;

		if (!task->stopped)
			break;
	}
}

static void mtrace_exit(void)
{
	if (!options.interactive) {
		each_process(stop_threads);
		each_process(detach_process);
	}

	each_process(remove_proc);
	each_pid(remove_task);
}

static void mtrace_init(char **cmd_args)
{
	struct opt_p_t *opt_p_tmp;

	mtrace_pid = getpid();

	if (options.command) {
		struct task *task = task_create(cmd_args);

		if (!task)
			exit(EXIT_FAILURE);

		if (unlikely(options.verbose))
			fprintf(stderr, "+++ process pid=%d created (%s)\n", task->pid, library_execname(task));
	}

	for(opt_p_tmp = options.opt_p; opt_p_tmp; opt_p_tmp = opt_p_tmp->next)
		open_pid(opt_p_tmp->pid);
}

static void mtrace_main(void)
{
	struct task *task;

	while(!do_exit)  {
		if (task_list_empty())
			break;

		task = next_event();
		if (task) {
			if (handle_event(task) == -1)
				break;
		}

		if (server_poll() == -1)
			break;
	}
}

int main(int argc, char *argv[])
{
	char **cmd_args = process_options(argc, argv);

	if (options.trace) {
		if (options.logfile) {
			if (server_logfile() == -1)
				exit(EXIT_FAILURE);
		}
		else
		if (options.server) {
			if (server_start() == -1)
				exit(EXIT_FAILURE);
		}
		else {
#ifdef DISABLE_CLIENT
			fprintf(stderr, "direct mode not supported\n");
			exit(EXIT_FAILURE);
#else
			int ret = server_start_pair();

			if (ret == -1)
				exit(EXIT_FAILURE);

			if (client_start_pair(ret))
				exit(EXIT_FAILURE);
#endif
		}
	}
	else {
#ifdef DISABLE_CLIENT
		fprintf(stderr, "direct mode not supported\n");
		exit(EXIT_FAILURE);
#else
		if (options.logfile) {
			if (client_logfile() == -1)
				exit(EXIT_FAILURE);
		}
		else
		if (client_start() == -1)
			exit(EXIT_FAILURE);
		return 0;
#endif
	}

	if (os_init())
		exit(EXIT_FAILURE);

	mtrace_init(cmd_args);
	mtrace_main();
	mtrace_exit();

	report_info(0);
	report_disconnect();

#ifndef DISABLE_CLIENT
	client_stop();
#endif
	server_stop();

	return 0;
}

