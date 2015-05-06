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

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <semaphore.h>

#include "backend.h"
#include "breakpoint.h"
#include "common.h"
#include "ioevent.h"
#include "main.h"
#include "memtrace.h"
#include "options.h"
#include "server.h"
#include "task.h"
#include "thread.h"
#include "trace.h"

#define MODE_NONE	0
#define MODE_COMMAND	1
#define MODE_ACCEPTED	2
#define MODE_DISCONNECT	3

static unsigned int server_mode = MODE_NONE;
static int listen_fd = -1;
static int server_fd = -1;
static struct thread *thread;
static int command_pending;
static sem_t sem;

static void stop_trace(struct task *leader)
{
	struct list_head *it;

	breakpoint_disable_all_nonlocked(leader);

	list_for_each(it, &leader->task_list) {
		struct task *task = container_of(it, struct task, task_list);

		task_reset_bp(task);
	}

	task_reset_bp(leader);
}

static void start_trace(struct task *leader)
{
	breakpoint_enable_all_nonlocked(leader);
}

int server_connected(void)
{
	return server_fd != -1;
}

static void server_close(void)
{
	if (server_connected()) {
		shutdown(server_fd, SHUT_RDWR);
		close(server_fd);
		server_fd = -1;
		each_process(&stop_trace);
	}
}

int server_poll(void)
{
	int ret = 0;

 	if (command_pending) {
		ret = server_handle_command();

		if (options.server)
			ret = 0;

		command_pending = 0;
		sem_post(&sem);
	}
	return ret;
}

static void request_server(void)
{
	command_pending = 1;
	wait_event_wakeup();
	thread_enable_cancel();
	TEMP_FAILURE_RETRY(sem_wait(&sem));
	thread_disable_cancel();
}

int server_handle_command(void)
{
	int ret;
	struct mt_msg cmd;
	void *payload = NULL;
	struct task *task;
	unsigned int mode = server_mode;

	server_mode = MODE_NONE;

	switch(mode) {
	case MODE_ACCEPTED:
		report_info(1);
		report_processes();

		each_process(&start_trace);
		return 0;
	case MODE_DISCONNECT:
		server_close();

		return -1;
	case MODE_COMMAND:
		break;
	default:
		break;
	}

	if (!server_connected())
		return -1;

	ret = safe_read(server_fd, &cmd, sizeof(cmd));

	if (ret != sizeof(cmd)) {
		if (ret > 0) {
			if (options.verbose)
				fprintf(stderr, "cmd read wrong size %d\n", ret);
		}
		server_close();

		return options.server ? 0: -1;
	}

	if (cmd.payload_len) {
		payload = malloc(cmd.payload_len);

		if (safe_read(server_fd, payload, cmd.payload_len) != (ssize_t)cmd.payload_len) {
			fprintf(stderr, "can't read payload_len (%u)\n", cmd.payload_len);
			goto finish;
		}
	}

	if (!cmd.pid) {
		server_close();
		goto finish;
	}

	task = pid2task(cmd.pid);
	if (!task)
		goto finish;

	if (task != task->leader)
		goto finish;

	switch(cmd.operation) {
	case MT_SCAN:
	 {
		unsigned long data_len = 0;
		void *data = NULL;

		stop_threads(task);

		data = mem_scan(task, &cmd, payload, &data_len);

		report_scan(cmd.pid, data, data_len);
		break;
	 }
	case MT_START:
		start_trace(task);
		break;
	case MT_STOP:
		stop_trace(task);
		break;
	case MT_DETACH:
		detach_proc(task);
		break;
	case MT_ABOUT_EXIT:
		continue_task(task, 0);
		break;
	default:
		break;
	}
finish:
	if (payload)
		free(payload);

	return cmd.operation;
}

static void *server_listen_thread(void *ptr)
{
	int ret;

	for(;;) {
		if (!server_connected()) {
			thread_enable_cancel();
			server_fd = TEMP_FAILURE_RETRY(accept(listen_fd, NULL, 0));
			thread_disable_cancel();

			if (server_fd < 0)
				fatal("accept (%s)", strerror(errno));

			server_mode = MODE_ACCEPTED;
		}
		else {
			thread_enable_cancel();
			ret = ioevent_wait_input(server_fd, -1);
			thread_disable_cancel();

			if (ret != 1)
				server_mode = MODE_DISCONNECT;
			else
				server_mode = MODE_COMMAND;
		}

		request_server();
	}
	return NULL;
}

int server_start(void)
{
	thread = thread_new();
	if (!thread)
		return -1;

	listen_fd = bind_to(options.listen, options.port);
	if (listen_fd < 0)
		fatal("colud not bind socket: %s:%s", options.listen, options.port);

	if (listen(listen_fd, 1) < 0)
		fatal("listen (%s)", strerror(errno));

	if (options.wait) {
		fprintf(stderr, "waiting for client connection...\n");

		server_fd = TEMP_FAILURE_RETRY(accept(listen_fd, NULL, 0));
		if (server_fd < 0)
			fatal("accept (%s)", strerror(errno));

		report_info(1);
		report_processes();

		each_process(&start_trace);
	}
	else {
		each_process(&stop_trace);
	}

	sem_init(&sem, 0, 1);

	if (thread_start(thread, server_listen_thread, NULL))
		fatal("could not start thread (%s)", strerror(errno));

	return 0;
}

static void *server_pair_thread(void *ptr)
{
	int ret;

	for(;;) {
		if (!server_connected())
			break;

		thread_enable_cancel();
		ret = ioevent_wait_input(server_fd, -1);
		thread_disable_cancel();

		if (ret != 1)
			server_mode = MODE_DISCONNECT;
		else
			server_mode = MODE_COMMAND;

		request_server();
	}

	return NULL;
}

int server_start_pair(void)
{
	int sv[2];

	thread = thread_new();
	if (!thread)
		return -1;

	if (create_socket_pair(sv) == -1)
		return -1;

	server_fd = sv[0];

	sem_init(&sem, 0, 1);

	if (thread_start(thread, server_pair_thread, NULL)) {
		thread_remove(thread);
		server_close();
		return -1;
	}

	report_processes();

	return sv[1];
}

int server_send_msg(enum mt_operation op, uint32_t pid, uint32_t tid, const void *payload, unsigned int payload_len)
{
	return sock_send_msg(server_fd, op, pid, tid, payload, payload_len);
}

int server_stop(void)
{
	thread_cancel(thread);
	if (thread)
		thread_join(thread);

	server_close();

	if (listen_fd != -1) {
		if (is_named(options.listen))
			unlink(options.listen);
		close(listen_fd);
		listen_fd = -1;
	}

	return 0;
}

