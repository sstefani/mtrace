/*
 * This file is part of mtrace.
 * Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
 *  This file is based on the ltrace source
 *   Copyright (C) 2012, 2013 Petr Machata, Red Hat Inc.
 *   Copyright (C) 2009,2010 Joe Damato
 *   Copyright (C) 1998,1999,2002,2003,2004,2007,2008,2009 Juan Cespedes
 *   Copyright (C) 2006 Ian Wienand
 *   Copyright (C) 2006 Steve Fink
 *   Copyright (C) 2006 Paul Gilliam, IBM Corporation
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

#include <sys/ioctl.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "options.h"

#ifndef SYSCONFDIR
#define SYSCONFDIR "/etc"
#endif

#define SYSTEM_CONFIG_FILE SYSCONFDIR "/mtrace.conf"
#define USER_CONFIG_FILE "~/.mtrace.conf"

#define MIN_STACK	4
#define MAX_STACK	128

#define DEFAULT_STACK	6
#define DEFAULT_PORT	4576

struct options_t options;

static char *progname;		/* Program name (`mtrace') */

static void err_usage(void)
{
	fprintf(stderr, "Try `%s --help' for more information.\n", progname);
	exit(1);
}

static void usage(void)
{
	fprintf(stdout,
		"Usage: %s [option ...] [command [arg ...]]\n"
		"\n"
		"Trace memory allocation library calls of a given program.\n"
		"\n"
		" -a, --autoscan      scan memory on exit of a traced program\n"
		" -b, --binpath=path  binary search path (may be repeated)\n"
		" -c, --client        connect to socket (path or address)\n"
		" -C, --cwd           set current working directory\n"
#ifdef DEBUG
		" -D, --debug=MASK    enable debugging (see -Dh or --debug=help)\n"
		" -Dh, --debug=help   show help on debugging\n"
#endif
		" -d, --depth=NR      backtrace stack depth (default: " STR(DEFAULT_STACK) ")\n"
		" -e, --follow-exec   follow exec() system calls\n"
		" -F, --config=FILE   load alternate configuration file (may be repeated)\n"
		" -f, --follow-child  trace forked children\n"
		" -h, --help          display this help and exit\n"
		" -i, --interactive   interactive client mode\n"
		" -l, --listen        listen on socket path or address in server mode\n"
		" -o, --output=FILE   write the trace output to file with given name\n"
		" -p, --pid=PID       attach to the process with the process ID pid (may be repeated)\n"
		" -P, --port=PORT     socket port (default: " STR(DEFAULT_PORT) ")\n"
		" -s, --server        server mode\n"
		" -S, --sort-by=type  sort dump by type:\n"
		"                      allocations, average, bytes-leaked, leaks, stacks, total, tsc, usage\n"
		" -u, --user=USERNAME run command with the userid, groupid of username\n"
		" -V, --version       output version information and exit\n"
		" -v, --verbose       verbose mode (repeat for higher verbosity)\n"
		" -w, --wait          wait for client connection\n"
		"\n"
		"Report bugs to stefani@seibold.net\n", progname);
}

#ifdef DEBUG
static void usage_debug(void)
{
	fprintf(stdout, "%s debugging option, --debug=<octal> or -D<octal>:\n", progname);
	fprintf(stdout,
		"\n"
		" number  ref. in source   description\n"
		"      1   general           Generally helpful progress information\n"
		"     10   event             Shows every event received by a traced process\n"
		"     20   process           Shows actions carried upon a traced processes\n"
		"     40   function          Shows every entry to internal functions\n"
		"\n"
		"Debugging options are mixed using bitwise-or.\n"
		"Note that the meanings and values are subject to change.\n"
	);
}
#endif

static char *search_for_command(char *filename)
{
	static char pathname[PATH_MAX];
	char *path;
	int m, n;

	if (strchr(filename, '/')) {
		return filename;
	}
	for (path = getenv("PATH"); path && *path; path += m) {
		if (strchr(path, ':')) {
			n = strchr(path, ':') - path;
			m = n + 1;
		} else {
			m = n = strlen(path);
		}
		if (n + strlen(filename) + 1 >= PATH_MAX) {
			fprintf(stderr, "Error: filename too long.\n");
			exit(1);
		}
		strncpy(pathname, path, n);
		if (n && pathname[n - 1] != '/') {
			pathname[n++] = '/';
		}
		strcpy(pathname + n, filename);
		if (!access(pathname, X_OK)) {
			return pathname;
		}
	}
	return filename;
}

static int parse_int(const char *optarg, char opt, int min, int max)
{
	char *endptr;
	long int l = strtol(optarg, &endptr, 0);
	if (l < min || (max != 0 && l > max)
	    || *optarg == 0 || *endptr != 0) {
		const char *fmt = max != 0 ? "Invalid argument to -%c: '%s'.  Use integer %d..%d.\n" : "Invalid argument to -%c: '%s'.  Use integer >=%d.\n";
		fprintf(stderr, fmt, opt, optarg, min, max);
		exit(1);
	}
	return (int)l;
}

char **process_options(int argc, char **argv)
{
	struct opt_F_t *opt_F_last = NULL;
	struct opt_p_t *opt_p_last = NULL;
	struct opt_b_t *opt_b_last = NULL;

	progname = argv[0];

	options.auto_scan = 0;
	options.output = stderr;
	options.bt_depth = DEFAULT_STACK;
	options.port = NULL;
	options.follow = 0;
	options.follow_exec = 0;
	options.interactive = 0;
	options.verbose = 0;
	options.wait = 0;
	options.client = NULL;
	options.server = 0;
	options.listen = NULL;
	options.user = NULL;
	options.command = NULL;
	options.cwd = -1;
	options.opt_p = NULL;
	options.opt_F = NULL;
	options.opt_b = NULL;
	options.sort_by = -1;
	options.debug = 0;

	for(;;) {
		int c;
		int option_index = 0;
		static const struct option long_options[] = {
			{ "auto_scan", 0, 0, 'a' },
			{ "binpath", 1, 0, 'b' },
			{ "client", 1, 0, 'c' },
			{ "config", 1, 0, 'F' },
			{ "cwd", 1, 0, 'C' },
			{ "debug", 1, 0, 'D' },
			{ "depth", 1, 0, 'd' },
			{ "help", 0, 0, 'h' },
			{ "follow-child", 0, 0, 'f'},
			{ "follow-exec", 0, 0, 'e' },
			{ "interactive", 0, 0, 'i' },
			{ "listen", 1, 0, 'l' },
			{ "output", 1, 0, 'o' },
			{ "pid", 1, 0, 'p' },
			{ "port", 1, 0, 'P' },
			{ "server", 0, 0, 's' },
			{ "sort-by", 1, 0, 'S' },
			{ "user", 1, 0, 'u' },
			{ "version", 0, 0, 'V' },
			{ "verbose", 0, 0, 'v' },
			{ "wait", 0, 0, 'w' },
			{ 0, 0, 0, 0 }
		};
		c = getopt_long(argc, argv,
				"+aefhisVvw"
				"b:c:C:D:F:l:o:p:P:u:d:S:",
				long_options,
				&option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'a':
			options.auto_scan = 1;
			break;
		case 'b':
			{
				struct opt_b_t *tmp = malloc(sizeof(*tmp));

				if (!tmp) {
					fprintf(stderr, "%s\n", strerror(errno));
					exit(1);
				}
				tmp->pathname = strdup(optarg);
				tmp->next = NULL;

				if (opt_b_last)
					opt_b_last->next = tmp;
				opt_b_last = tmp;

				if (!options.opt_b)
					options.opt_b = tmp;
				break;
			}
		case 'c':
			options.client = optarg;
			break;
		case 'C':
			options.cwd = open(optarg, O_RDONLY|O_DIRECTORY);

			if (options.cwd == -1) {
				fprintf(stderr, "%s: `%s' %s\n", progname, optarg, strerror(errno));
				exit(1);
			}
			break;
		case 'D':
			{
#ifdef DEBUG
				char *p;
				if (optarg[0] == 'h') {
					usage_debug();
					exit(0);
				}
				options.debug = strtoul(optarg, &p, 8);
				if (*p) {
					fprintf(stderr, "%s: --debug requires an octal argument\n", progname);
					err_usage();
				}
#endif
				break;
			}
		case 'f':
			options.follow = 1;
			break;
		case 'F':
			{
				struct opt_F_t *tmp = malloc(sizeof(*tmp));

				if (!tmp) {
					fprintf(stderr, "%s\n", strerror(errno));
					exit(1);
				}
				tmp->filename = optarg;
				tmp->next = NULL;

				if (opt_F_last)
					opt_F_last->next = tmp;
				opt_F_last = tmp;

				if (!options.opt_F)
					options.opt_F = tmp;
				break;
			}

		case 'h':

			usage();
			exit(0);
		case 'i':
			options.interactive = 1;
			break;
		case 'l':
			options.listen = optarg;
			break;
		case 'o':
			options.output = fopen(optarg, "w");
			if (!options.output) {
				fprintf(stderr, "can't open %s for writing: %s\n", optarg, strerror(errno));
				exit(1);
			}
			setvbuf(options.output, (char *)NULL, _IOLBF, 0);
			fcntl(fileno(options.output), F_SETFD, FD_CLOEXEC);
			break;
		case 'p':
			{
				struct opt_p_t *tmp = malloc(sizeof(*tmp));

				if (!tmp) {
					fprintf(stderr, "%s\n", strerror(errno));
					exit(1);
				}
				tmp->pid = parse_int(optarg, 'p', 1, 0);
				tmp->next = NULL;

				if (opt_p_last)
					opt_p_last->next = tmp;
				opt_p_last = tmp;

				if (!options.opt_p)
					options.opt_p = tmp;
				break;
			}
		case 'P':
			options.port = optarg;
			break;
		case 'u':
			options.user = optarg;
			break;
		case 'V':
			printf("mtrace version " PACKAGE_VERSION ".\n"
			       "Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>.\n"
			       "\n"
			       "This software was sponsored by Rohde & Schwarz GmbH & Co. KG, Munich.\n"
			       "\n"
			       "This is free software; see the GNU General Public Licence\n"
			       "version 2 or later for copying conditions. There is NO warranty.\n");
			exit(0);
		case 'd':
			options.bt_depth = parse_int(optarg, 'd', 1, 0);
			break;
		case 'e':
			options.follow_exec = 1;
			break;
		case 'v':
			options.verbose++;
			break;
		case 'w':
			options.wait = 1;
			break;
		case 's':
			options.server = 1;
			break;
		case 'S':
			if (!strncmp(optarg, "allocations", 2))
				options.sort_by = OPT_SORT_ALLOCATIONS;
			else
			if (!strncmp(optarg, "average", 2))
				options.sort_by = OPT_SORT_AVERAGE;
			else
			if (!strncmp(optarg, "bytes-leaked", 1))
				options.sort_by = OPT_SORT_BYTES_LEAKED;
			else
			if (!strncmp(optarg, "leaks", 1))
				options.sort_by = OPT_SORT_LEAKS;
			else
			if (!strncmp(optarg, "stacks", 1))
				options.sort_by = OPT_SORT_STACKS;
			else
			if (!strncmp(optarg, "total", 2))
				options.sort_by = OPT_SORT_TOTAL;
			else
			if (!strncmp(optarg, "tsc", 2))
				options.sort_by = OPT_SORT_TSC;
			else
			if (!strncmp(optarg, "usage", 1))
				options.sort_by = OPT_SORT_USAGE;
			else {
				fprintf(stderr, "invalid sort paramter: %s\n", optarg);
				exit(1);
			}
			break;
		default:
			err_usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (options.sort_by == OPT_SORT_LEAKS || options.sort_by == OPT_SORT_BYTES_LEAKED)
		options.auto_scan = 1;

	if (!options.client && !options.opt_p && argc < 1) {
		fprintf(stderr, "%s: too few arguments\n", progname);
		err_usage();
	}

	if (!options.server && options.listen) {
		fprintf(stderr, "%s: listen mode can only valid in server mode\n", progname);
		err_usage();
	}

	if (options.client && (options.opt_p || argc > 0)) {
		fprintf(stderr, "%s: client mode does not require -p nor executable\n", progname);
		err_usage();
	}
	else

	if (options.client && options.server) {
		fprintf(stderr, "%s: choose between client and server mode\n", progname);
		err_usage();
	}

	if (options.opt_b && !options.client) {
		fprintf(stderr, "%s: binpath can only used in client mode\n", progname);
		err_usage();
	}

	if (options.interactive && (!options.client && !options.opt_p)) {
		fprintf(stderr, "%s: interactive mode can only invoked in -p or -c mode\n", progname);
		err_usage();
	}

	if (options.auto_scan && options.server) {
		fprintf(stderr, "%s: scan option can not passed in -s mode\n", progname);
		err_usage();
	}

	if (options.port) {
		if (!options.client && !options.server) {
			fprintf(stderr, "%s: Port only valid in client or server mode \n", progname);
			err_usage();
		}
	}
	else
		options.port = STR(DEFAULT_PORT);

	if (options.sort_by != -1 && options.server) {
		fprintf(stderr, "%s: sort-by can not passed in -s mode\n", progname);
		err_usage();
	}

	if (options.bt_depth < MIN_STACK)
		options.bt_depth = MIN_STACK;
	else
	if (options.bt_depth > MAX_STACK)
		options.bt_depth = MAX_STACK;

	if (!options.opt_F) {
		options.opt_F = malloc(sizeof(struct opt_F_t));
		options.opt_F->filename = USER_CONFIG_FILE;
		options.opt_F->next = malloc(sizeof(struct opt_F_t));
		options.opt_F->next->filename = SYSTEM_CONFIG_FILE;
		options.opt_F->next->next = NULL;
	}

	if (argc > 0)
		options.command = search_for_command(argv[0]);

	return &argv[0];
}

