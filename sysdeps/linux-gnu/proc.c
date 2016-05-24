/*
 * This file is part of mtrace-ng.
 * Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
 *  This file is based on the ltrace source
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

#define _GNU_SOURCE		/* For getline.  */

#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <link.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "backend.h"
#include "breakpoint.h"
#include "config.h"
#include "debug.h"
#include "event.h"
#include "library.h"
#include "mtelf.h"
#include "task.h"

/* /proc/pid doesn't exist just after the fork, and sometimes `mtrace-ng'
 * couldn't open it to find the executable.  So it may be necessary to
 * have a bit delay
 */

#define PROC_PID_FILE(VAR, FORMAT, PID)		\
	char VAR[strlen(FORMAT) + 6];		\
	sprintf(VAR, FORMAT, PID)

/*
 * Returns a (malloc'd) file name corresponding to a running pid
 */
char *pid2name(pid_t pid)
{
	PROC_PID_FILE(proc_exe, "/proc/%d/exe", pid);

	if (kill(pid, 0))
		return NULL;

	return strdup(proc_exe);
}

/*
 * Returns a (malloc'd) file name corresponding to a running pid
 */
char *pid2cwd(pid_t pid)
{
	int ret;
	char fname[PATH_MAX];
	PROC_PID_FILE(proc_cwd, "/proc/%d/cwd", pid);

	ret = readlink(proc_cwd, fname, sizeof(fname) - 1);
	if (ret == -1)
		return NULL;

	fname[ret] = 0;

	return strdup(fname);
}

static FILE *open_status_file(pid_t pid)
{
	PROC_PID_FILE(fn, "/proc/%d/status", pid);
	/* Don't complain if we fail.  This would typically happen
	   when the process is about to terminate, and these files are
	   not available anymore.  This function is called from the
	   event loop, and we don't want to clutter the output just
	   because the process terminates.  */
	return fopen(fn, "r");
}

static char *find_line_starting(FILE *file, const char *prefix, size_t len)
{
	char *line = NULL;
	size_t line_len = 0;
	while (!feof(file)) {
		if (getline(&line, &line_len, file) < 0)
			return NULL;
		if (strncmp(line, prefix, len) == 0)
			return line;
	}
	return NULL;
}

static void each_line_starting(FILE *file, const char *prefix, void (*cb)(const char *line, const char *prefix, void *data), void *data)
{
	size_t len = strlen(prefix);
	char *line;

	while ((line = find_line_starting(file, prefix, len)) != NULL) {
		(*cb)(line, prefix, data);
		free(line);
		break;
	}
}

static void process_leader_cb(const char *line, const char *prefix, void *data)
{
	*(pid_t *)data = atoi(line + strlen(prefix));
}

pid_t process_leader(pid_t pid)
{
	pid_t tgid = 0;
	FILE *file = open_status_file(pid);

	if (file != NULL) {
		each_line_starting(file, "Tgid:\t", &process_leader_cb, &tgid);
		fclose(file);
	}
	return tgid;
}

static int all_digits(const char *str)
{
	while (isdigit(*str))
		str++;
	return !*str;
}

int process_tasks(pid_t pid, pid_t ** ret_tasks, size_t *ret_n)
{
	pid_t *tasks = NULL;
	size_t n = 0;
	size_t alloc = 0;

	PROC_PID_FILE(fn, "/proc/%d/task", pid);
	DIR *d = opendir(fn);

	if (!d)
		return -1;

	for(;;) {
		struct dirent entry;
		struct dirent *result;

		if (readdir_r(d, &entry, &result) != 0) {
			free(tasks);
			return -1;
		}

		if (result == NULL)
			break;

		if (result->d_type == DT_DIR && all_digits(result->d_name)) {
			pid_t npid = atoi(result->d_name);

			if (n >= alloc) {
				pid_t *ntasks;

				alloc = n > 0 ? (2 * n) : 8;

				ntasks = realloc(tasks, sizeof(*tasks) * alloc);
				if (!ntasks) {
					free(tasks);
					return -1;
				}
				tasks = ntasks;
			}
			tasks[n++] = npid;
		}
	}

	closedir(d);

	*ret_tasks = tasks;
	*ret_n = n;

	return 0;
}

/* On native 64-bit system, we need to be careful when handling cross
 * tracing.  This select appropriate pointer depending on host and
 * target architectures.  XXX Really we should abstract this into the
 * ABI object, as theorized about somewhere on pmachata/revamp
 * branch.  */
static void *select_32_64(struct task *task, void *p32, void *p64)
{
	if (sizeof(long) == 4 || !task_is_64bit(task))
		return p32;
	else
		return p64;
}

static int fetch_dyn64(struct task *task, arch_addr_t *addr, Elf64_Dyn *ret)
{
	if (copy_from_proc(task, *addr, ret, sizeof(*ret)) != sizeof(*ret))
		return -1;
	*addr += sizeof(*ret);
	return 0;
}

static int fetch_dyn32(struct task *task, arch_addr_t *addr, Elf64_Dyn *ret)
{
	Elf32_Dyn dyn;

	if (copy_from_proc(task, *addr, &dyn, sizeof(dyn)) != sizeof(dyn))
		return -1;

	*addr += sizeof(dyn);
	ret->d_tag = dyn.d_tag;
	ret->d_un.d_val = dyn.d_un.d_val;

	return 0;
}

static int (*dyn_fetcher(struct task *task)) (struct task *, arch_addr_t *, Elf64_Dyn *)
{
	return select_32_64(task, fetch_dyn32, fetch_dyn64);
}

static int process_find_dynamic_entry_addr(struct task *leader, arch_addr_t src_addr, int d_tag, arch_addr_t *ret)
{
	for(;;) {
		Elf64_Dyn entry;

		if (dyn_fetcher(leader) (leader, &src_addr, &entry) < 0 || entry.d_tag == DT_NULL) {
			debug(DEBUG_FUNCTION, "Couldn't find address for dtag!");
			return -1;
		}

		if (entry.d_tag == d_tag) {
			*ret = ARCH_ADDR_T(entry.d_un.d_val);

			debug(DEBUG_FUNCTION, "found address: %#lx in dtag %d", *ret, d_tag);
			return 0;
		}
	}
}

/* Our own type for representing 32-bit linkmap.  We can't rely on the
 * definition in link.h, because that's only accurate for our host
 * architecture, not for target architecture (where the traced process
 * runs). */
#define LT_LINK_MAP(BITS)			\
	{					\
		Elf##BITS##_Addr l_addr;	\
		Elf##BITS##_Addr l_name;	\
		Elf##BITS##_Addr l_ld;		\
		Elf##BITS##_Addr l_next;	\
		Elf##BITS##_Addr l_prev;	\
	}

struct lt_link_map_32 LT_LINK_MAP(32);
struct lt_link_map_64 LT_LINK_MAP(64);

static int fetch_lm64(struct task *task, arch_addr_t addr, struct lt_link_map_64 *ret)
{
	if (copy_from_proc(task, addr, ret, sizeof(*ret)) != sizeof(*ret))
		return -1;
	return 0;
}

static int fetch_lm32(struct task *task, arch_addr_t addr, struct lt_link_map_64 *ret)
{
	struct lt_link_map_32 lm;

	if (copy_from_proc(task, addr, &lm, sizeof(lm)) != sizeof(lm))
		return -1;

	ret->l_addr = lm.l_addr;
	ret->l_name = lm.l_name;
	ret->l_ld = lm.l_ld;
	ret->l_next = lm.l_next;
	ret->l_prev = lm.l_prev;

	return 0;
}

static int (*lm_fetcher(struct task *task)) (struct task *, arch_addr_t, struct lt_link_map_64 *)
{
	return select_32_64(task, fetch_lm32, fetch_lm64);
}

/* The same as above holds for struct r_debug.  */
#define LT_R_DEBUG(BITS)			\
	{					\
		int r_version;			\
		Elf##BITS##_Addr r_map;		\
		Elf##BITS##_Addr r_brk;		\
		int r_state;			\
		Elf##BITS##_Addr r_ldbase;	\
	}

struct lt_r_debug_32 LT_R_DEBUG(32);
struct lt_r_debug_64 LT_R_DEBUG(64);

static int fetch_rd64(struct task *task, arch_addr_t addr, struct lt_r_debug_64 *ret)
{
	if (copy_from_proc(task, addr, ret, sizeof(*ret)) != sizeof(*ret))
		return -1;
	return 0;
}

static int fetch_rd32(struct task *task, arch_addr_t addr, struct lt_r_debug_64 *ret)
{
	struct lt_r_debug_32 rd;

	if (copy_from_proc(task, addr, &rd, sizeof(rd)) != sizeof(rd))
		return -1;

	ret->r_version = rd.r_version;
	ret->r_map = rd.r_map;
	ret->r_brk = rd.r_brk;
	ret->r_state = rd.r_state;
	ret->r_ldbase = rd.r_ldbase;

	return 0;
}

static int (*rdebug_fetcher(struct task *task))(struct task *, arch_addr_t, struct lt_r_debug_64 *)
{
	return select_32_64(task, fetch_rd32, fetch_rd64);
}

static int fetch_auxv64_entry(int fd, Elf64_auxv_t *ret)
{
	/* Reaching EOF is as much problem as not reading whole
	 * entry.  */
	return read(fd, ret, sizeof(*ret)) == sizeof(*ret) ? 0 : -1;
}

static int fetch_auxv32_entry(int fd, Elf64_auxv_t *ret)
{
	Elf32_auxv_t auxv;

	if (read(fd, &auxv, sizeof(auxv)) != sizeof(auxv))
		return -1;

	ret->a_type = auxv.a_type;
	ret->a_un.a_val = auxv.a_un.a_val;
	return 0;
}

static int (*auxv_fetcher(struct task *task)) (int, Elf64_auxv_t *) {
	return select_32_64(task, fetch_auxv32_entry, fetch_auxv64_entry);
}

static void linkmap_add(struct task *task, struct lt_r_debug_64 *dbg)
{
	struct library *lib;

	debug(DEBUG_FUNCTION, "pid=%d", task->pid);

	if (!dbg || !dbg->r_map) {
		debug(DEBUG_FUNCTION, "Debug structure or it's linkmap are NULL!");
		return;
	}

	arch_addr_t addr = ARCH_ADDR_T(dbg->r_map);

	while (addr) {
		struct lt_link_map_64 rlm;

		if (lm_fetcher(task) (task, addr, &rlm) < 0) {
			fprintf(stderr, "Unable to read link map\n");
			return;
		}

		addr = ARCH_ADDR_T(rlm.l_next);

		if (rlm.l_name == 0) {
			fprintf(stderr, "Name of mapped library is NULL\n");
			continue;
		}

		/* Do we have that library already?  */
		lib = library_find_with_key(&task->libraries_list, ARCH_ADDR_T(rlm.l_ld));
		if (lib)
			continue;

		char lib_name[PATH_MAX];

		copy_str_from_proc(task, ARCH_ADDR_T(rlm.l_name), lib_name, sizeof(lib_name));

		if (
			strcmp(lib_name, "") == 0 ||
			strcmp(lib_name, "linux-vdso.so.1") == 0 ||
			strcmp(lib_name, "linux-gate.so.1") == 0 ||
			strcmp(lib_name, "linux-vdso32.so.1") == 0 ||
			strcmp(lib_name, "linux-vdso64.so.1") == 0
		)
			continue;

		struct libref *libref = libref_new(LIBTYPE_LIB);

		if (!libref) {
			fprintf(stderr, "Couldn't instance library object %s\n", lib_name);
			continue;
		}

		if (elf_read_library(task, libref, lib_name, rlm.l_addr) < 0) {
			libref_delete(libref);
			fprintf(stderr, "Couldn't load ELF object %s\n", lib_name);
			continue;
		}

		library_add(task, libref);
	}

	return;
}

static void linkmap_del(struct task *task, struct lt_r_debug_64 *dbg)
{
	struct library *lib;

	debug(DEBUG_FUNCTION, "pid=%d", task->pid);

	if (!dbg || !dbg->r_map) {
		debug(DEBUG_FUNCTION, "Debug structure or it's linkmap are NULL!");
		return;
	}

	LIST_HEAD(tmp_list);

	list_splice_init(&task->libraries_list, &tmp_list);

	/* first entry in the map list is the binary itself */
	list_move(tmp_list.next, &task->libraries_list);

	arch_addr_t addr = ARCH_ADDR_T(dbg->r_map);

	while (addr) {
		struct lt_link_map_64 rlm;

		if (lm_fetcher(task) (task, addr, &rlm) < 0) {
			fprintf(stderr, "Unable to read link map\n");
			return;
		}

		addr = ARCH_ADDR_T(rlm.l_next);

		lib = library_find_with_key(&tmp_list, ARCH_ADDR_T(rlm.l_ld));
		if (lib)
			list_move_tail(&lib->list, &task->libraries_list);
	}

	library_delete_list(task, &tmp_list);

	return;
}

static int load_debug_struct(struct task *task, arch_addr_t debug_addr, struct lt_r_debug_64 *ret)
{
	debug(DEBUG_FUNCTION, "pid=%d", task->pid);

	if (rdebug_fetcher(task) (task, debug_addr, ret) < 0) {
		debug(DEBUG_FUNCTION, "This process does not have a debug structure!");
		return -1;
	}

	return 0;
}

static int rdebug_bp_on_hit(struct task *task, struct breakpoint *bp)
{
	struct lt_r_debug_64 rdbg;
	struct task *leader = task->leader;

	debug(DEBUG_FUNCTION, "pid=%d", task->pid);

	if (load_debug_struct(task, leader->os.debug_addr, &rdbg) < 0)
		return 0;

	if (rdbg.r_state == RT_CONSISTENT) {
		debug(DEBUG_FUNCTION, "Linkmap is now consistent");
		switch (leader->os.debug_state) {
		case RT_ADD:
			linkmap_add(task, &rdbg);
			break;
		case RT_DELETE:
			linkmap_del(task, &rdbg);
			break;
		default:
			debug(DEBUG_FUNCTION, "Unexpected debug state!");
		}
	}

	leader->os.debug_state = rdbg.r_state;
	return 0;
}

int linkmap_init(struct task *task, arch_addr_t dyn_addr)
{
	struct lt_r_debug_64 rdbg;
	struct breakpoint *bp;
	arch_addr_t debug_addr;
	struct task *leader = task->leader;

	debug(DEBUG_FUNCTION, "pid=%d, dyn_addr=%#lx", task->pid, dyn_addr);

	if (leader->os.debug_addr)
		return 0;

	if (process_find_dynamic_entry_addr(task, dyn_addr, DT_DEBUG, &debug_addr) == -1) {
		debug(DEBUG_FUNCTION, "Couldn't find debug structure!");
		return -1;
	}

	if (!debug_addr)
		return -1;

	if (load_debug_struct(task, debug_addr, &rdbg) < 0)
		return -1;

	arch_addr_t addr = ARCH_ADDR_T(rdbg.r_brk);

	bp = breakpoint_new(task, addr, NULL, BP_SW);
	if (!bp)
		return -1;

	bp->on_hit = rdebug_bp_on_hit;
	bp->locked = 1;

	breakpoint_enable(task, bp);

	leader->os.debug_addr = debug_addr;

	if (rdbg.r_state == RT_CONSISTENT)
		linkmap_add(task, &rdbg);

	return 0;
}

int process_get_entry(struct task *task, unsigned long *entryp, unsigned long *interp_biasp)
{
	PROC_PID_FILE(fn, "/proc/%d/auxv", task->pid);
	int fd, ret;

	fd = open(fn, O_RDONLY);
	if (fd == -1)
		goto fail;

	GElf_Addr at_entry = 0;
	GElf_Addr at_bias = 0;

	while (1) {
		Elf64_auxv_t entry = { };
		if (auxv_fetcher(task)(fd, &entry) < 0)
			goto fail;

		if (entry.a_type == AT_NULL)
			break;

		switch (entry.a_type) {
		case AT_BASE:
			at_bias = entry.a_un.a_val;
			break;
		case AT_ENTRY:
			at_entry = entry.a_un.a_val;
			break;
		case AT_NULL:
			break;
		default:
			break;
		}
	}

	if (entryp != NULL)
		*entryp = at_entry;
	if (interp_biasp != NULL)
		*interp_biasp = at_bias;

	ret = 0;
	goto done;
fail:
	fprintf(stderr, "couldn't read %s: %s", fn, strerror(errno));
	ret = -1;
done:
	if (fd != -1)
		close(fd);
	return ret;
}

int os_task_init(struct task *task)
{
	if (task == task->leader) {
		task->os.debug_addr = 0;
		task->os.debug_state = RT_ADD;
	}
	return 0;
}

void os_task_destroy(struct task *task)
{
}

int os_task_clone(struct task *retp, struct task *task)
{
	struct task *leader = task->leader;

	retp->os = leader->os;
	return 0;
}

