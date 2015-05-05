/*
 * This file is part of mtrace.
 * Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
 *  This file is based on the ltrace source
 *
 * This work was sponsored by Rohde & Schwarz GmbH & Co. KG, Munich.
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

#ifndef _INC_OPTIONS_H
#define _INC_OPTIONS_H

#include <sys/types.h>

#include "config.h"
#include "forward.h"

#define OPT_SORT_ALLOCATIONS	0
#define OPT_SORT_AVERAGE	1
#define OPT_SORT_BYTES_LEAKED	2
#define OPT_SORT_LEAKS		3
#define OPT_SORT_STACKS		4
#define OPT_SORT_TOTAL		5
#define OPT_SORT_TSC		6
#define OPT_SORT_USAGE		7

struct options_t options;

struct opt_p_t {
	pid_t pid;
	struct opt_p_t *next;
};

struct opt_F_t {
	const char *filename;
	struct opt_F_t *next;
};

struct opt_b_t {
	char *pathname;
	struct opt_b_t *next;
};

struct options_t {
	int auto_scan;		/* scan memory on every exit of a trace program */
	int bt_depth;		/* how may levels of stack frames to show */
	int follow;		/* trace child processes */
	int follow_exec;	/* follow exec system calls */
	int interactive;	/* interactive mode */
	FILE *output;		/* output to a specific file */
	int server;		/* server mode flag */
	int kill;		/* kill on errors */
	char *listen;		/* server listen on socket path or address */
	char *client;		/* connect to socket path or address */
	char *user;		/* -u: username to run command as */
	int verbose;		/* verbose mode */
	int wait;		/* wait for client connection */
	char *port;		/* socket port */
	char *command;		/* command string */
	int cwd;		/* current working directory handle */
	struct opt_p_t *opt_p;	/* attach to process with a given pid */
	struct opt_F_t *opt_F;	/* alternate configuration file(s) */
	struct opt_b_t *opt_b;	/* binary search path(s) */
	int sort_by;		/* sort dump in non interative and non server mode */
	int debug;		/* debug */
	int nocpp;		/* disable trace of c++ allocation operators */
};

char **process_options(int argc, char **argv);

#endif

