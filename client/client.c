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

#include <byteswap.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <signal.h>

#include "binfile.h"
#include "common.h"
#include "client.h"
#include "dump.h"
#include "ioevent.h"
#include "options.h"
#include "process.h"
#include "readline.h"
#include "rbtree.h"
#include "socket.h"
#include "thread.h"

struct rb_process {
	struct rb_node node;
	struct process *process;
};

static int client_fd;

static struct rb_root pid_table;
static int first_pid;
static struct memtrace_info mt_info;
static struct thread *thread;
static int pipefd[2];

static unsigned long skip_nl(const char *p, unsigned long n)
{
	unsigned long c = 0;

	while(n > c) {
		if (p[c] != '\n' && p[c] != '\r')
			break;
		++c;
	}

	return c;
}

static unsigned long get_line(const char *p, unsigned long n)
{
	unsigned long c = 0;

	while(n > c) {
		if (p[c] == '\n' || p[c] == '\r')
			break;
		++c;
	}

	return c;
}

static unsigned long skip_space(const char *p, unsigned long n)
{
	unsigned long c = 0;

	while(n > c) {
		if (p[c] != ' ' && p[c] != '\t')
			break;
		++c;
	}

	return c;
}

static unsigned long trim_space(const char *p, unsigned long n)
{
	unsigned long c = n;

	while(c) {
		if (p[c - 1] != ' ' && p[c - 1] != '\t')
			break;
		--c;
	}

	return c;
}

static unsigned long cmp_n(const char *p, const char *str, unsigned long n)
{
	unsigned long c = 0;

	while(n > c) {
		if (!str[c]) {
			if (p[c] == ' ' || p[c] == '\t')
				return c;
			break;
		}

		if (p[c] != str[c])
			break;

		c++;
	}

	return 0;
}

static void _parse_config(const char *filename, const char *p, unsigned long n)
{
	unsigned long c, l;

	for(;;) {
		c = skip_nl(p, n);

		p += c;
		n -= c;

		if (!n)
			break;

		l = get_line(p, n);

		c = skip_space(p, l);

		p += c;
		n -= c;
		l -= c;

		if (!n)
			break;

		if (*p != '#') {
			c = cmp_n(p, "ignore", l);
			if (c) {
				c += skip_space(p + c, l - c);

				if (c != l) {
					int ret;
					regex_t	re;
					char *regex;

					regex = strndup(p + c, trim_space(p + c, l - c));

					ret = regcomp(&re, regex, REG_NOSUB);
					if (ret) {
						char errbuf[128];

						regerror(ret, &re, errbuf, sizeof(errbuf));

						fprintf(stderr, "%s: invalid regular expression: `%s' (%s)\n", filename, regex, errbuf);
					}
					else
						add_ignore_regex(&re);

					free(regex);
				}
			}
			else
				fprintf(stderr, "%s: invalid line `%.*s'\n", filename, (int)l, p);
		}

		p += l;
		n -= l;

		if (!n)
			break;
	}
}

static int parse_config(const char *filename)
{
	char *p;
	struct stat statbuf;
	int fd;
	
	fd = open(filename, O_RDONLY);
	if (fd == -1)
		fatal("could not open config file: `%s' (%s)", filename, strerror(errno));

	if (fstat(fd, &statbuf) == -1)
		fatal("could not read config file: `%s' (%s)", filename, strerror(errno));

	if (statbuf.st_size) {
		p = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (p == MAP_FAILED)
			fatal("could map config file: `%s' (%s)", filename, strerror(errno));

		_parse_config(filename, p, statbuf.st_size);

		munmap(p, statbuf.st_size);
	}
	close(fd);

	return 0;
}

static struct rb_process *pid_rb_search(struct rb_root *root, pid_t pid)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct rb_process *data = (struct rb_process *) node;

		if (pid < data->process->pid)
			node = node->rb_left;
		else if (pid > data->process->pid)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

static struct process *pid_rb_delete(struct rb_root *root, pid_t pid)
{
	struct rb_process *data = pid_rb_search(root, pid);
	struct process *process;

	if (data) {
		process = data->process;
		
		rb_erase(&data->node, root);
		free(data);
	
		return process;
	}
	return NULL;
}

static int process_rb_insert(struct rb_root *root, struct process *process)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct rb_process *data;

	/* Figure out where to put new node */
	while (*new) {
		struct rb_process *this = (struct rb_process *) *new;

		parent = *new;
		if (process->pid < this->process->pid)
			new = &((*new)->rb_left);
		else if (process->pid > this->process->pid)
			new = &((*new)->rb_right);
		else
			return FALSE;
	}

	data = malloc(sizeof(*data));
	data->process = process;

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);

	return TRUE;
}

static void swap_msg(struct mt_msg *mt_msg)
{
	mt_msg->operation = bswap_16(mt_msg->operation);
	mt_msg->payload_len = bswap_32(mt_msg->payload_len);
	mt_msg->pid = bswap_32(mt_msg->pid);
	mt_msg->tid = bswap_32(mt_msg->tid);
}

static int socket_read_msg(struct mt_msg *mt_msg, void **payload, unsigned int *swap_endian)
{
	if (TEMP_FAILURE_RETRY(safe_read(client_fd, mt_msg, sizeof(*mt_msg))) <= 0)
		return FALSE;

	if (mt_msg->operation > 0xff) {
		swap_msg(mt_msg);

		*swap_endian = 1;
	}
	else
		*swap_endian = 0;

	if (mt_msg->payload_len) {
		*payload = malloc(mt_msg->payload_len);

		if (TEMP_FAILURE_RETRY(safe_read(client_fd, *payload, mt_msg->payload_len)) <= 0)
			return FALSE;
	}

	return TRUE;
}

static pid_t pid_payload(struct process *process, void *payload)
{
	struct mt_pid_payload *mt_pid = payload;

	return process->val32(mt_pid->pid);
}

static unsigned int attached_payload(void *payload)
{
	struct mt_attached_payload *mt_attached = payload;

	return mt_attached->attached;
}

void client_close(void)
{
	if (client_fd != -1) {
		ioevent_del_input(client_fd);
		shutdown(client_fd, SHUT_RDWR);
		close(client_fd);
		client_fd = -1;
	}
}

static void client_broken(void)
{
	if (client_fd != -1) {
		fprintf(stderr, "connection lost\n");
		client_close();
	}
}

static int client_func(void)
{
	struct mt_msg mt_msg;
	struct process *process;
	void *payload = NULL;
	unsigned int swap_endian;

	if (socket_read_msg(&mt_msg, &payload, &swap_endian) == FALSE) {
		client_broken();
		return -1;
	}

	if (!mt_msg.pid) {
		process = NULL;

		switch(mt_msg.operation) {
		case MT_DISCONNECT:
			sock_send_msg(client_fd, MT_DISCONNECT, 0, 0, NULL, 0);
			client_close();
			break;
		case MT_INFO:
			memcpy(&mt_info, payload, sizeof(mt_info));
			break;
		default:
			fatal("protocol violation 0x%08x", mt_msg.operation);
		}
	}
	else {
		process = client_find_process(mt_msg.pid);
		if (!process) {
			process = process_new(mt_msg.pid, swap_endian, mt_info.do_trace);

			client_add_process(process);
		}
		else {
			if (process->swap_endian != swap_endian)
				process = NULL;
			else
			if (process->status == MT_PROCESS_IGNORE)
				process = NULL;
		}
	}

	if (process) {
		switch(mt_msg.operation) {
		case MT_MALLOC:
		case MT_REALLOC:
		case MT_REALLOC_FAILED:
		case MT_MEMALIGN:
		case MT_POSIX_MEMALIGN:
		case MT_ALIGNED_ALLOC:
		case MT_VALLOC:
		case MT_PVALLOC:
		case MT_MMAP:
		case MT_MMAP64:
			process_alloc(process, &mt_msg, payload);
			break;
		case MT_REALLOC_ENTER:
		case MT_FREE:
			process_free(process, &mt_msg, payload);
			break;
		case MT_MUNMAP:
			process_munmap(process, &mt_msg, payload);
			break;
		case MT_FORK:
			process_duplicate(process, client_find_process(pid_payload(process, payload)));
			break;
		case MT_ATTACH:
			process_reinit(process, swap_endian, 0, attached_payload(payload));
			break;
		case MT_ATTACH64:
			if (!IS64BIT) {
				fprintf(stderr, "64 bit processes with pid %d not supported on 32 bit hosts\n", mt_msg.pid);
				process_set_status(process, MT_PROCESS_IGNORE);
				break;
			}
			process_reinit(process, swap_endian, 1, attached_payload(payload));
			break;
		case MT_ABOUT_EXIT:
			process_about_exit(process);
			break;
		case MT_EXIT:
			process_exit(process);
			break;
		case MT_NOFOLLOW:
			process_delete(process);
			break;
		case MT_SCAN:
			process_scan(process, payload, mt_msg.payload_len);
			break;
		case MT_ADD_MAP:
			process_add_map(process, payload, mt_msg.payload_len);
			break;
		case MT_DEL_MAP:
			process_del_map(process, payload, mt_msg.payload_len);
			break;
		case MT_DETACH:
			process_detach(process);
			break;
		default:
			fatal("protocol violation 0x%08x", mt_msg.operation);
		}
	}

	if (payload)
		free(payload);

	return mt_msg.operation;
}

void client_show_info(void)
{
	printf("memtrace info:\n");
	printf(" follow fork: %s\n", mt_info.mode & MEMTRACE_SI_FORK ? "yes" : "no");
	printf(" follow exec: %s\n", mt_info.mode & MEMTRACE_SI_EXEC ? "yes" : "no");
	printf(" verbose: %s\n", mt_info.mode & MEMTRACE_SI_VERBOSE ? "yes" : "no");
	printf(" do trace: %s\n", mt_info.do_trace ? "yes" : "no");
	printf(" stack depth: %u\n", mt_info.stack_depth);
}

int client_wait_op(enum mt_operation op)
{
	for(;;) {
		if (client_fd == -1)
			return -1;

		if (ioevent_wait_input(client_fd, -1) <= 0)
			break;

		if (client_func() == (int)op)
			break;
	}
	return 0;
}

static int client_release_process(struct rb_node *node, void *user)
{
	struct rb_process *data = (struct rb_process *)node;

	process_delete(data->process);
	free(data);
	return 0;
}

void client_finalize()
{
	client_close();

	rb_iterate(&pid_table, client_release_process, NULL);
}

static int client_iterate_process(struct rb_node *node, void *user)
{
	struct rb_process *data = (struct rb_process *)node;
	int (*func)(struct process *process) = user;

	return func(data->process);
}

void client_iterate_processes(int (*func)(struct process *process))
{
	rb_iterate(&pid_table, client_iterate_process, func);
}

struct process *client_find_process(pid_t pid)
{
	struct rb_process *data;

	data = pid_rb_search(&pid_table, pid);
	if (data)
		return data->process;
	return NULL;
}

struct process *client_first_process(void)
{
	if (!first_pid)
		return NULL;
	return client_find_process(first_pid);
}

void client_add_process(struct process *process)
{
	if (!first_pid)
		first_pid = process->pid;

	process_rb_insert(&pid_table, process);
}

void client_remove_process(struct process *process)
{
	process = pid_rb_delete(&pid_table, process->pid);

	if (process)
		free(process);
}


static int client_init(int do_trace)
{
	struct opt_F_t *p;

	pid_table = RB_ROOT;
	first_pid = 0;

	mt_info.version = MEMTRACE_SI_VERSION;
	mt_info.mode = 0;
	mt_info.do_trace = do_trace;
	mt_info.stack_depth = 0;

	for(p = options.opt_F; p; p = p->next) {
		if (parse_config(p->filename) < 0)
			return -1;
	}

	return 0;
}

static void signal_exit(int sig)
{
	const char signum = sig;

	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);

	if (write(pipefd[1], &signum, 1) == -1)
		;
}

static int scan_process(struct process *process)
{
	if (options.auto_scan) {
		process_leaks_scan(process, SCAN_ALL);
		client_wait_op(MT_SCAN);
	}
	else
		process_dump_sortby(process);

	return 0;
}

static int signal_func(void)
{
	fprintf(stderr, "terminating...\n");
	client_iterate_processes(scan_process);
	exit(0);
}

int client_start(void)
{
	if (client_init(0) < 0)
		return -1;

	client_fd = connect_to(options.client, options.port);

	if (client_fd == -1) {
		fprintf(stderr, "could not connect: %s:%s\n", options.client, options.port);
		return -1;
	}

	client_wait_op(MT_INFO);

	if (mt_info.version != MEMTRACE_SI_VERSION) {
		fprintf(stderr,
			"client version v%u does not match client version v%u\n",
			mt_info.version,
			MEMTRACE_SI_VERSION
		);

		return -1;
	}

	client_show_info();

	ioevent_add_input(client_fd, client_func);

	if (options.interactive) {
		readline_init();

		while(ioevent_watch(-1) != -1)
			;
	}
	else {
		if (pipe(pipefd) == -1) {
			fprintf(stderr, "could not create pipe (%s)", strerror(errno));
			return -1;
		}

		ioevent_add_input(pipefd[0], signal_func);

		signal(SIGINT, signal_exit);	/* Detach task_es when interrupted */
		signal(SIGTERM, signal_exit);	/* ... or killed */

		while(client_fd != -1) {
			if (ioevent_watch(-1) == -1)
				break;
		}
	}

	return 0;
}

void *client_thread(void *unused)
{
	while(client_fd != -1)
		client_func();

	return NULL;
}

int client_start_pair(int handle)
{
	if (client_init(1) < 0)
		return -1;

	thread = thread_new();
	if (!thread)
		return -1;

	client_fd = handle;

	if (thread_start(thread, client_thread, NULL))
		fatal("could not start thread (%s)", strerror(errno));

	return 0;
}

int client_send_msg(struct process *process, enum mt_operation op, void *payload, unsigned int payload_len)
{
	int ret = sock_send_msg(client_fd, process->val16(op), process->pid, 0, payload, payload_len);

 	if (ret < 0)
		client_broken();
	return ret;
}

int client_connected(void)
{
	if (client_fd != -1)
		return 1;

	printf("connection lost\n");

	return 0;
}

int client_stop(void)
{
	if (thread)
		thread_join(thread);
	client_close();
	return 0;
}

