/*
 * This file is part of mtrace.
 * Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
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

#ifndef _INC_CLIENT_PROCESS_H
#define _INC_CLIENT_PROCESS_H

#include <regex.h>

#include "list.h"
#include "memtrace.h"
#include "rbtree.h"

#define SCAN_ALL	0
#define SCAN_LEAK	1
#define SCAN_NEW	2

struct alloc_block;

enum process_status {
	MT_PROCESS_RUNNING,	/* process is running */
	MT_PROCESS_EXIT,	/* _exit() has been called in process */
	MT_PROCESS_EXITING,	/* process is about exiting */
	MT_PROCESS_IGNORE,	/* ignore the process */
	MT_PROCESS_DETACH,	/* trace will be detached */
};

struct lib {
	struct list_head list;
	const char *pathname;
	unsigned long offset;
	unsigned long addr;
	unsigned long size;
};

struct process {
	enum process_status status;
	pid_t pid;
	char *filename;
	unsigned long bytes_used;
	unsigned long n_allocations;
	unsigned long total_allocations;
	unsigned long leaks;
	unsigned long long leaked_bytes;
	unsigned long stack_trees;
	struct rb_root block_table;
	struct rb_root stack_table;
	struct list_head map_list;
	unsigned long long tsc;
	unsigned int tracing:1;
	unsigned int swap_endian:1;
	unsigned int is_64bit:1;
	unsigned int attached:1;
	unsigned long (*get_ulong)(void *);
	void (*put_ulong)(void *, unsigned long);
	uint16_t (*val16)(uint16_t val);
	uint32_t (*val32)(uint32_t val);
	uint64_t (*val64)(uint64_t val);
	uint8_t ptr_size;
};

struct process *process_new(pid_t pid, unsigned int swap_endian, unsigned int tracing);
void process_reset_allocations(struct process *process);
void process_reinit(struct process *process, unsigned int swap_endian, unsigned int is_64bit, unsigned int attached);
void process_set_clone(struct process *process, struct process *clone);
struct process *process_clone_of(struct process *process);
void process_delete(struct process *process);
void process_duplicate(struct process *process, struct process *copy);
void process_run(struct process *process, const char *libpath, const char *path, char **args);
void process_set_status(struct process *process, enum process_status status);
void process_start_input(struct process *process);
void process_stop_input(struct process *process);
void process_about_exit(struct process *process);
void process_exit(struct process *process);
void process_status(struct process *process);
void *process_scan(struct process *curr, void *leaks, uint32_t payload_len);
void process_alloc(struct process *process, struct mt_msg *msg, void *payload);
void process_free(struct process *process, struct mt_msg *msg, void *payload);
void process_munmap(struct process *process, struct mt_msg *msg, void *payload);
void process_add_map(struct process *process, void *payload, uint32_t payload_len);
void process_del_map(struct process *process, void *payload, uint32_t payload_len);
void process_detach(struct process *process);

unsigned long process_leaks_scan(struct process *process, int mode);

void process_dump_sort_average(struct process *process, const char *outfile);
void process_dump_sort_usage(struct process *process, const char *outfile);
void process_dump_sort_leaks(struct process *process, const char *outfile);
void process_dump_sort_bytes_leaked(struct process *process, const char *outfile);
void process_dump_sort_allocations(struct process *process, const char *outfile);
void process_dump_sort_total(struct process *process, const char *outfile);
void process_dump_sort_tsc(struct process *process, const char *outfile);
void process_dump_stacks(struct process *process, const char *outfile);

void add_ignore_regex(regex_t *re);

#endif

