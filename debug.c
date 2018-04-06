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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "common.h"
#include "options.h"

#include "debug.h"

#ifdef DEBUG

void _debug(int level, const char *file, const char *function, int line, const char *fmt, ...)
{
	char *buf = NULL;
	va_list args;

	if (!(options.debug & level))
		return;

	va_start(args, fmt);
	if (vasprintf(&buf, fmt, args) == -1)
		abort();
	va_end(args);

	fprintf(stderr, "DEBUG: %s():%s@%d - %s\n", function, file, line, buf);

//	fflush(debug_file);
	free(buf);
}

#endif

