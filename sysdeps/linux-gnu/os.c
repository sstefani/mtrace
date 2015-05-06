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

#include "config.h"

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <bfd.h>
#include <pwd.h>
#include <grp.h>

#include "backend.h"
#include "breakpoint.h"
#include "common.h"
#include "debug.h"
#include "main.h"
#include "options.h"
#include "os.h"
#include "socket.h"
#include "task.h"

struct map {
	unsigned long long start;
	unsigned long long end;
};
 
static void report_fault(int signo, siginfo_t* siginf, void* arg)
{
	int nptrs;
	int i;
	void *trace[48];
	char **strings;
	Dl_info info;
 	char linkname[PATH_MAX];
	bfd* abfd = 0;
	asymbol **syms = 0;
	asection *text = 0;
	int l;

	fprintf(stderr, "fault signal %d (%s)\n", signo, strsignal(signo));

	l = readlink("/proc/self/exe", linkname, sizeof(linkname));
 	if (l == -1) {
		perror("failed to find executable\n");
		return;
 	}
	linkname[l] = 0;
 
	bfd_init();
 
 	abfd = bfd_openr(linkname, 0);
 	if (!abfd) {
 		perror("bfd_openr failed: ");
 		return;
 	}
 
	/* oddly, this is required for it to work... */
 	bfd_check_format(abfd,bfd_object);
 
 	unsigned storage_needed = bfd_get_symtab_upper_bound(abfd);
 	syms = (asymbol **) malloc(storage_needed);

 	bfd_canonicalize_symtab(abfd, syms);

	text = bfd_get_section_by_name(abfd, ".text");
 
	nptrs = backtrace(trace, ARRAY_SIZE(trace));

	strings = backtrace_symbols(trace, nptrs);
	if (!strings) {
		perror("backtrace_symbols");
		_exit(EXIT_FAILURE);
	}

	for (i = 0; i < nptrs; ++i) {
		unsigned long offset;

		fprintf(stderr, "%d:%s", i, strings[i]);

		offset = ((long)trace[i]) - text->vma;

		if (offset < text->size) {
			const char *file;
			const char *func;
			unsigned line;

			if (bfd_find_nearest_line(abfd, text, syms, offset, &file, &func, &line) && file) {
				fprintf(stderr, ": %s()", func);
				if (*file)
					fprintf(stderr, ":%s@%u", file, line);
				goto skip;
			}
		}

		if (dladdr(trace[i], &info)) {
			if (info.dli_sname)
				fprintf(stderr, ": %s", info.dli_sname);
		}
skip:
		fprintf(stderr, "\n");
	}

	free(strings);

	fflush(stderr);

	_exit(EXIT_FAILURE);
}

static void signal_exit(int sig)
{
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);

	mtrace_request_exit();
}

static void sigchld_handler(int signum)
{
}

static int open_mem(pid_t pid)
{
	int h;
	char *proc_name;

	if (asprintf(&proc_name, "/proc/%u/mem", pid) == -1)
		fatal("asprintf (%s)", strerror(errno));

	h = open(proc_name, O_RDONLY);
	if (h == -1)
		fatal("open: '%s'(%s)", proc_name, strerror(errno));

	free(proc_name);

	return h;
}

static struct map *get_writeable_mappings(struct task *task)
{
	unsigned long long start;
	unsigned long long end;
	char permr;
	char permw;
	char filename[PATH_MAX + 2];
	char nl;
	FILE *in;
	unsigned int maps_size = 0;
	struct map *maps = NULL;
	unsigned int map = 0;

	snprintf(filename, sizeof(filename)-1, "/proc/%d/maps", task->pid);

	maps_size = 16;
	maps = malloc(maps_size * sizeof(*maps));

	in = fopen(filename, "r");
	if (!in)
		goto skip;

	while(fscanf(in, "%llx-%llx %c%c%*c%*c %*x %*x:%*x %*u%*64[ ]%c", &start, &end, &permr, &permw, filename) == 5) {
		if (*filename != '\n') {
			if (fscanf(in, "%" STR(PATH_MAX) "[^\n]%c", filename + 1, &nl) != 2)
				break;
			if (nl != '\n')
				break;
		}
		else
			*filename = 0;

		if (*filename != '[' && *filename != 0) {
			struct stat statbuf;

			if (stat(filename, &statbuf) < 0)
				continue;

			if (S_ISCHR(statbuf.st_mode)) {
				if (statbuf.st_rdev != makedev(1, 5))
					continue;
			}
		}

		if (permw != 'w' || permr != 'r')
			continue;
		
		if (map >= maps_size - 1) {
			maps_size += 16;
			maps = realloc(maps, maps_size * sizeof(*maps));
		}

		maps[map].start = start;
		maps[map].end = end;

		map++;
	}

	fclose(in);
skip:
	maps[map].start = 0;
	maps[map].end = 0;

	return maps;
}

void *mem_scan(struct task *task, struct mt_msg *cmd, void *payload, unsigned long *data_len)
{
	struct mt_scan_payload *mt_scan = payload;
	unsigned long mask = (unsigned long)mt_scan->mask;
	uint32_t ptr_size = mt_scan->ptr_size;
	void *blocks = mt_scan->data;
	unsigned long n = (cmd->payload_len - (blocks - payload)) / ptr_size;
	unsigned long map;
	struct map *maps;
	int h;
	unsigned long (*get_val)(void *data, unsigned long index);
	unsigned long start;
	unsigned long end;

	if (!n)
		return NULL;

	if (ptr_size == sizeof(uint32_t))
		get_val = get_val32;
	else
		get_val = get_val64;

	h = open_mem(task->pid);
	if (h == -1)
		return NULL;

	maps = get_writeable_mappings(task);

	for(map = 0; (start = maps[map].start) && (end = maps[map].end); ++map) {
		int do_peek = 0;

		while(start < end) {
			unsigned long i;
			char page_buf[PAGE_SIZE];

			if (!do_peek) {
				if (lseek(h, start, SEEK_SET) != (off_t)start || read(h, page_buf, sizeof(page_buf)) == -1)
					do_peek = 1;
			}

			if (do_peek) {
				if (copy_from_proc(task, ARCH_ADDR_T(start), page_buf, sizeof(page_buf)) != sizeof(page_buf)) {
					fprintf(stderr, "ptrace (%s)\n", strerror(errno));
					break;
				}
			}

			for(i = 0; i < sizeof(page_buf) / ptr_size; ++i) {
				unsigned long found, addr;

				addr = get_val(page_buf, i);

				if (addr & mask)
					continue;

				found = find_block(get_val, blocks, n, addr);
				if (found != n) {
					if (!--n)
						goto finish;

					if (found != n)
						memmove(blocks + found * ptr_size, blocks + (found + 1) * ptr_size, (n - found) * ptr_size);
				}
			}

			start += sizeof(page_buf);
		}
	}

finish:
	close(h);

	*data_len = n * ptr_size;

	free(maps);

	return blocks;
}

void change_uid(const char *command)
{
	uid_t run_uid, run_euid;
	gid_t run_gid, run_egid;

	if (options.user) {
		struct passwd *pent;

		if (getuid() != 0 || geteuid() != 0) {
			fprintf(stderr, "you must be root to use the -u option\n");
			exit(1);
		}
		if ((pent = getpwnam(options.user)) == NULL) {
			fprintf(stderr, "cannot find user `%s'\n", options.user);
			exit(1);
		}
		run_uid = pent->pw_uid;
		run_gid = pent->pw_gid;

		if (initgroups(options.user, run_gid) < 0) {
			perror("mtrace: initgroups");
			exit(1);
		}
	} else {
		run_uid = getuid();
		run_gid = getgid();
	}
	if (options.user || !geteuid()) {
		struct stat statbuf;
		run_euid = run_uid;
		run_egid = run_gid;

		if (!stat(options.command, &statbuf)) {
			if (statbuf.st_mode & S_ISUID) {
				run_euid = statbuf.st_uid;
			}
			if (statbuf.st_mode & S_ISGID) {
				run_egid = statbuf.st_gid;
			}
		}
		if (setregid(run_gid, run_egid) < 0) {
			perror("mtrace: setregid");
			exit(1);
		}
		if (setreuid(run_uid, run_euid) < 0) {
			perror("mtrace: setreuid");
			exit(1);
		}
	}
}

ssize_t sock_fd_write(int sock, void *buf, ssize_t buflen, int fd)
{
	ssize_t		size;
	struct msghdr	msg;
	struct iovec	iov;

	iov.iov_base = buf;
	iov.iov_len = buflen;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	size = sendmsg(sock, &msg, MSG_DONTWAIT);

	return size;
}

int os_init(void)
{
	sigset_t block_sigset;
	struct sigaction act;
	const int siglist[] = { SIGSEGV, SIGABRT, SIGTRAP, SIGILL, SIGFPE };
	unsigned int i;
	int ret;

	for(i = 0; i < ARRAY_SIZE(siglist); i++) {
		act.sa_flags = SA_ONESHOT | SA_SIGINFO;
		act.sa_sigaction = report_fault;
		sigfillset(&act.sa_mask);
		sigaction(siglist[i], &act, NULL);
	}

	signal(SIGINT, signal_exit);	/* Detach task_es when interrupted */
	signal(SIGTERM, signal_exit);	/* ... or killed */

	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	act.sa_handler = sigchld_handler;

	if (sigaction(SIGCHLD, &act, NULL)) {
		perror("sigaction(SIGCHLD)");
		return -1;
	}

	sigemptyset(&block_sigset);
	sigaddset(&block_sigset, SIGCHLD);

	ret = pthread_sigmask(SIG_BLOCK, &block_sigset, NULL);
	if (ret) {
		fprintf(stderr, "pthread_sigmask %d (%s)\n", ret, strerror(ret));
		return -1;
	}

	return 0;
}

