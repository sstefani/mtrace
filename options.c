/*
 * This file is part of mtrace.
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

#define _GNU_SOURCE

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
#include <sys/types.h>
#include <pwd.h>

#include "common.h"
#include "options.h"

#ifndef SYSCONFDIR
#define SYSCONFDIR "/etc"
#endif

#define MIN_STACK	4
#define MAX_STACK	64

#define DEFAULT_STACK	15
#define DEFAULT_PORT	4576

static char *sockdef;

struct options_t options;

static struct opt_F_t *opt_F_last;
static struct opt_p_t *opt_p_last;
static struct opt_b_t *opt_b_last;
static struct opt_O_t *opt_O_last;

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
		" -c, --cwd=path      use as current working directory for traced process\n"
#ifdef DEBUG
		" -D, --debug=MASK    enable debugging (see -Dh or --debug=help)\n"
		" -Dh, --debug=help   show help on debugging\n"
#endif
		" -d, --depth=NR      backtrace stack depth (default: " STR(DEFAULT_STACK) ")\n"
		" -e, --follow-exec   follow exec() system calls\n"
		" -F, --config=FILE   load alternate configuration file (may be repeated)\n"
		" -f, --follow-fork   trace forked children\n"
		" -h, --help          display this help and exit\n"
		" -i, --interactive   interactive client mode\n"
		" -O, --omit=FILE     do not place breakpoint in this file\n"
		" -k, --kill          abort mtrace on unexpected error conditon\n"
		" -l, --logfile       use log file instead of socket connection\n"
		" -n, --nocpp         disable trace of c++ allocation operators (faster for libstdc++)\n"
		" -o, --output=FILE   write the trace output to file with given name\n"
		" -p, --pid=PID       attach to the process with the process ID pid (may be repeated)\n"
		" -P, --port=PORT     socket port (default: " STR(DEFAULT_PORT) ")\n"
		" -r, --remote=addr   remote use address (path, address or host)\n"
		" -s, --sort-by=type  sort dump by type:\n"
		"                      allocations, average, bytes-leaked, leaks, stacks, total, tsc, usage\n"
		" -t, --trace         trace mode\n"
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

	if (strchr(filename, '/'))
		return filename;

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

		if (n && pathname[n - 1] != '/')
			pathname[n++] = '/';

		strcpy(pathname + n, filename);

		if (!access(pathname, X_OK))
			return pathname;
	}
	return filename;
}

static int add_opt_F(char *filename)
{
	struct opt_F_t *tmp = malloc(sizeof(*tmp));

	if (access(filename, R_OK))
		return -1;

	if (!tmp) {
		fprintf(stderr, "%s\n", strerror(errno));
		exit(1);
	}

	tmp->filename = strdup(filename);
	tmp->next = NULL;

	if (opt_F_last)
		opt_F_last->next = tmp;
	opt_F_last = tmp;

	if (!options.opt_F)
		options.opt_F = tmp;

	return 0;
}

static void def_config(void)
{
	char *path;
	char *filename;
		
	path = getenv("HOME");
	if (!path) {
		struct passwd *pwd = getpwuid(getuid());

		if (pwd != NULL)
			path = pwd->pw_dir;
	}

	if (path) {
		if (asprintf(&filename, "%s/.mtrace", path) != -1) {
			if (!add_opt_F(filename))
				return;
			free(filename);
		}
	}

	path = getenv("XDG_CONFIG_HOME");
	if (path)  {
		if (asprintf(&filename, "%s/mtrace", path) != -1) {
			if (!add_opt_F(filename))
				return;
			free(filename);
		}
	}

	if (asprintf(&filename, "%s/mtrace.conf", SYSCONFDIR) != -1) {
		if (!add_opt_F(filename))
			return;
		free(filename);
	}

	if (asprintf(&filename, "%s/mtrace.conf", "/etc") != -1) {
		if (!add_opt_F(filename))
			return;
		free(filename);
	}
}

static int parse_int(const char *optarg, char opt, int min, int max)
{
	char *endptr;
	long int l = strtol(optarg, &endptr, 0);

	if (l < min || (max != 0 && l > max) || *optarg == 0 || *endptr != 0) {
		const char *fmt = max != 0 ? "Invalid argument to -%c: '%s'.  Use integer %d..%d.\n" : "Invalid argument to -%c: '%s'.  Use integer >=%d.\n";
		fprintf(stderr, fmt, opt, optarg, min, max);
		exit(1);
	}
	return (int)l;
}

char **process_options(int argc, char **argv)
{
	char *output = NULL;
	char *cwd = NULL;

	if (!sockdef)
		asprintf(&sockdef, "/tmp/mtrace%u.sock", getuid());

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
	options.address = NULL;
	options.trace = 0;
	options.server = 0;
	options.logfile = NULL;
	options.user = NULL;
	options.command = NULL;
	options.cwd = -1;
	options.opt_p = NULL;
	options.opt_F = NULL;
	options.opt_b = NULL;
	options.opt_O = NULL;
	options.sort_by = -1;
	options.debug = 0;
	options.kill = 0;
	options.nocpp = 0;

	for(;;) {
		int c;
		int option_index = 0;
		static const struct option long_options[] = {
			{ "auto_scan", 0, 0, 'a' },
			{ "binpath", 1, 0, 'b' },
			{ "config", 1, 0, 'F' },
			{ "cwd", 1, 0, 'c' },
			{ "debug", 1, 0, 'D' },
			{ "depth", 1, 0, 'd' },
			{ "help", 0, 0, 'h' },
			{ "follow-fork", 0, 0, 'f'},
			{ "follow-exec", 0, 0, 'e' },
			{ "interactive", 0, 0, 'i' },
			{ "kill", 0, 0, 'k' },
			{ "logfile", 1, 0, 'l' },
			{ "nocpp", 1, 0, 'n' },
			{ "output", 1, 0, 'o' },
			{ "omit", 1, 0, 'O' },
			{ "pid", 1, 0, 'p' },
			{ "port", 1, 0, 'P' },
			{ "remote", 1, 0, 'r' },
			{ "sort-by", 1, 0, 's' },
			{ "trace", 0, 0, 't' },
			{ "user", 1, 0, 'u' },
			{ "version", 0, 0, 'V' },
			{ "verbose", 0, 0, 'v' },
			{ "wait", 0, 0, 'w' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv,
				"+aefhikLntVvw"
				"b:c:d:D:F:l:o:O:p:P:r:s:u:",
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
			cwd = optarg;
			break;
		case 'd':
			options.bt_depth = parse_int(optarg, 'd', 1, 0);
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
		case 'e':
			options.follow_exec = 1;
			break;
		case 'f':
			options.follow = 1;
			break;
		case 'F':
			if (add_opt_F(optarg) == -1) {
				fprintf(stderr, "config file not found %s\n", optarg);
				exit(1);
			}
			break;
		case 'h':
			usage();
			exit(0);
		case 'i':
			options.interactive = 1;
			break;
		case 'k':
			options.kill = 1;
			break;
		case 'l':
			options.logfile = optarg;
			break;
		case 'o':
			output = optarg;
			break;
		case 'O':
			{
				struct opt_O_t *tmp = malloc(sizeof(*tmp));

				if (!tmp) {
					fprintf(stderr, "%s\n", strerror(errno));
					exit(1);
				}
				tmp->pathname = strdup(optarg);
				tmp->next = NULL;

				if (opt_O_last)
					opt_O_last->next = tmp;
				opt_O_last = tmp;

				if (!options.opt_O)
					options.opt_O = tmp;
				break;
			}
		case 'n':
			options.nocpp = 1;
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
		case 'r':
			options.address = optarg;
			break;
		case 's':
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
		case 't':
			options.trace = 1;
			break;
		case 'u':
			options.user = optarg;
			break;
		case 'V':
			printf("mtrace version " PACKAGE_VERSION ".\n"
			       "Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>.\n"
			       "\n"
			       "This software was sponsored by Rohde & Schwarz GmbH & Co. KG, Munich/Germany.\n"
			       "\n"
			       "This is free software; see the GNU General Public Licence\n"
			       "version 2 or later for copying conditions. There is NO warranty.\n");
			exit(0);
		case 'v':
			options.verbose++;
			break;
		case 'w':
			options.wait = 1;
			break;
		default:
			err_usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 0)
		options.command = search_for_command(argv[0]);


	if (options.address && options.logfile) {
		fprintf(stderr, "%s: either logfile or remote address is valid\n", progname);
		err_usage();
	}

	if (options.trace) {
		if (!options.opt_p && !options.command) {
			fprintf(stderr, "%s: trace requires -p or executable\n", progname);
			err_usage();
		}

		if (options.auto_scan) {
			fprintf(stderr, "%s: scan option can not passed in when trace mode\n", progname);
			err_usage();
		}

		if (options.sort_by != -1) {
			fprintf(stderr, "%s: sort-by can not passed in trace mode\n", progname);
			err_usage();
		}

		if (options.opt_b) {
			fprintf(stderr, "%s: binpath can only used in client mode\n", progname);
			err_usage();
		}

		if (options.address) {
			if (!strcmp(options.address, "."))
				options.address = sockdef;

			options.server = 1;
		}
	}
	else {
		if (options.opt_p || options.command) {
			fprintf(stderr, "%s: client mode does not require -p nor executable\n", progname);
			err_usage();
		}

		if (options.nocpp) {
			fprintf(stderr, "%s: client mode does not require -n\n", progname);
			err_usage();
		}

		if (options.user) {
			fprintf(stderr, "%s: user can only passed in trace mode\n", progname);
			err_usage();
		}

		if (!options.address)
			options.address = sockdef;
	}

	if (options.interactive) {
		if (options.server) {
			fprintf(stderr, "%s: interactive mode not available in server mode\n", progname);
			err_usage();
		}

		if (options.trace) {
			if (options.command) {
				fprintf(stderr, "%s: cannot execute process and interactive console at the same time in trace mode\n", progname);
				err_usage();
			}

			if (!options.opt_p) {
				fprintf(stderr, "%s: interactive console requieres -p in trace mode\n", progname);
				err_usage();
			}
		}


		if (options.auto_scan) {
			fprintf(stderr, "%s: auto scan ignored in interactive mode\n", progname);
			options.auto_scan = 0;
		}

		if (options.sort_by != -1) {
			fprintf(stderr, "%s: sort-by ignored in interactive mode\n", progname);
			options.sort_by = -1;
		}
	}

	if (output) {
		if (options.interactive) {
			fprintf(stderr, "%s: output not valid in interactive mode\n", progname);
			err_usage();
		}

		if (options.logfile) {
			fprintf(stderr, "%s: either logfile or output is valid\n", progname);
			err_usage();
		}

		if (options.server) {
			fprintf(stderr, "%s: output not valid in server mode\n", progname);
			err_usage();
		}
	}

	if (options.port) {
		if (!options.address) {
			fprintf(stderr, "%s: port only valid in client or trace mode\n", progname);
			err_usage();
		}
	}
	else
		options.port = STR(DEFAULT_PORT);

	if (options.sort_by == OPT_SORT_LEAKS || options.sort_by == OPT_SORT_BYTES_LEAKED)
		options.auto_scan = 1;

	if (options.bt_depth < MIN_STACK)
		options.bt_depth = MIN_STACK;
	else
	if (options.bt_depth > MAX_STACK)
		options.bt_depth = MAX_STACK;

	if (!options.opt_F)
		def_config();

	if (output) {
		options.output = fopen(output, "w");

		if (!options.output) {
			fprintf(stderr, "can't open %s for writing: %s\n", output, strerror(errno));
			exit(1);
		}
		setvbuf(options.output, (char *)NULL, _IOLBF, 0);
		fcntl(fileno(options.output), F_SETFD, FD_CLOEXEC);
	}

	if (cwd) {
		options.cwd = open(cwd, O_RDONLY|O_DIRECTORY);

		if (options.cwd == -1) {
			fprintf(stderr, "%s: `%s' %s\n", progname, optarg, strerror(errno));
			exit(1);
		}
	}

	return &argv[0];
}

