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

#ifndef _INC_MEMTRACE_H
#define _INC_MEMTRACE_H

#include <stdint.h>

#if __LP64__
#define	IS64BIT	1
#else
#define	IS64BIT	0
#endif

#define	MEMTRACE_SI_VERSION	7

#define	MEMTRACE_SI_FORK	1
#define	MEMTRACE_SI_EXEC	2
#define	MEMTRACE_SI_VERBOSE	4

enum mt_operation {
	MT_INFO = 0,
	MT_DISCONNECT,
	MT_ADD_MAP,
	MT_DEL_MAP,
	MT_ATTACH,
	MT_ATTACH64,
	MT_FORK,
	MT_ABOUT_EXIT,
	MT_EXIT,
	MT_NOFOLLOW,
	MT_MALLOC,
	MT_REALLOC_ENTER,
	MT_REALLOC_DONE,
	MT_REALLOC,
	MT_FREE,
	MT_MMAP,
	MT_MMAP64,
	MT_MUNMAP,
	MT_MEMALIGN,
	MT_POSIX_MEMALIGN,
	MT_ALIGNED_ALLOC,
	MT_VALLOC,
	MT_PVALLOC,
	MT_SCAN,
	MT_STOP,
	MT_START,
	MT_DETACH,
	MT_NEW,
	MT_NEW_ARRAY,
	MT_DELETE,
	MT_DELETE_ARRAY,
	MT_DEPTH,
};

struct __attribute__((packed)) mt_msg {
	uint16_t operation;
	uint16_t pid;
	uint32_t payload_len;
};

struct __attribute__((packed)) mt_attached_payload {
	uint8_t attached;
};

struct __attribute__((packed)) mt_alloc_payload_64 {
	uint64_t ptr;
	uint64_t size;
	uint64_t data[0];
};

struct __attribute__((packed)) mt_alloc_payload_32 {
	uint32_t ptr;
	uint32_t size;
	uint32_t data[0];
};

struct __attribute__((packed)) mt_pid_payload {
	uint32_t pid;
};

struct __attribute__((packed)) mt_scan_payload {
	uint32_t ptr_size;
	uint64_t mask;
	char data[0];
};

struct __attribute__((packed)) memtrace_timer_info {
	uint32_t max;
	uint32_t count;
	uint64_t culminate;
};

struct __attribute__((packed)) memtrace_info {
	uint8_t	version;
	uint8_t	mode;
	uint8_t	do_trace;
	uint8_t stack_depth;
	uint8_t verbose;
	uint8_t unused[3];
	struct memtrace_timer_info stop_time;
	struct memtrace_timer_info sw_bp_time;
	struct memtrace_timer_info hw_bp_time;
	struct memtrace_timer_info backtrace_time;
	struct memtrace_timer_info reorder_time;
	struct memtrace_timer_info report_in_time;
	struct memtrace_timer_info report_out_time;
	struct memtrace_timer_info skip_bp_time;
};

struct __attribute__((packed)) memtrace_depth {
	uint8_t stack_depth;
};

struct __attribute__((packed)) mt_map_payload {
	uint64_t addr;
	uint64_t offset;
	uint64_t size;
	char filename[0];
};

#endif

