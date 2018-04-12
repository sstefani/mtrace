/*
 * This file is part of mtrace-ng.
 * Copyright (C) 2018 Stefani Seibold <stefani@seibold.net>
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
#include <string.h> 
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <termios.h>
#include <stdarg.h>
#include <ncurses.h>

#include "dump.h"
#include "ioevent.h"

static int dump_term;
static FILE *dump_outfile;
static int dump_char;

static int rows, cols;
static int row, col;

static int get_term_size(void)
{
#ifdef TIOCGSIZE
	struct ttysize ttys;
#endif
#ifdef TIOCGWINSZ
	struct winsize wins;
#endif
	const char *s;

#ifdef TIOCGSIZE
	if (ioctl(0, TIOCGSIZE, &ttys) != -1) {
		rows = ttys.ts_lines;
		cols = ttys.ts_cols;
		return 0;
	}
#endif
#ifdef TIOCGWINSZ
	if (ioctl(0, TIOCGWINSZ, &wins) != -1) {
		rows = wins.ws_row;
		cols = wins.ws_col;
		return 0;
	}
#endif
	if (rows) {
		s = getenv("LINES");
		if (s)
			rows = strtol(s, NULL, 10);
		else
			rows = 25;
	}

	if (cols) {
		s=getenv("COLUMNS");
		if (s)
			cols = strtol(s, NULL, 10);
		else
			cols = 80;
	}


	return 0;
}

int dump_init(FILE *file)
{
	dump_outfile = file;

	if (!dump_outfile) {
		dump_term = 0;
		row = 0;
		col = 0;
		get_term_size();
	}

	return 0;
}

static int dump_getchar(void)
{
	dump_char = getchar();
	return 0;
}

static int dump_pager(void)
{
	struct termios termios;
	struct termios termios_old;
	int len;
	ioevent_func oldfunc;

	len = printf("Press <space> for next line, q for quit and any other for next page\r") - 1;
	fflush(stdout);

	tcgetattr(0, &termios_old);
	termios = termios_old;
	cfmakeraw(&termios);

	tcsetattr(0, TCSADRAIN, &termios);
	oldfunc = ioevent_set_input_func(0, dump_getchar);

	dump_char = 0;
	do {
		ioevent_watch(-1);
	} while(!dump_char);

	ioevent_set_input_func(0, oldfunc);
	tcsetattr(0, TCSANOW, &termios_old);

	printf("%*s\r", len, "");
	fflush(stdout);

	switch(dump_char) {
	case '\03':
	case 'q':
		if (col)
			fputc('\n', stdout);
		dump_term = 1;
		return -1;
	case ' ':
		get_term_size();
		row = rows - 1;
		break;
	default:
		get_term_size();
		row = 0;
		break;
	}

	return 0;
}

static int next_nl(char *str, int l)
{
	int n;

	for(n = 0; *str; ++n) {
		if (!l--)
			break;

		if (*str++ == '\n')
			break;
	}
	return n;
}

static int dump_line(char *s, int n)
{
	if (dump_term)
		return -1;

	col += fwrite(s, sizeof(char), n, stdout);

	if (s[n] == '\n') {
		if (col < cols)
			fputc('\n', stdout);
		row++;
		col = 0;
	}
	else {
		if (col >= cols) {
			row++;
			col = 0;
		}
	}

	if (row >= rows) {
		if (dump_pager())
			return -1;
	}
	return 0;
}

int dump_printf(const char *fmt, ...)
{
	char *str;
	char *s;
	int n;
	va_list args;
	int ret = 0;

	if (dump_outfile) {
		va_start(args, fmt);
		vfprintf(dump_outfile, fmt, args);
		va_end(args);
		return 0;
	}

	va_start(args, fmt);
	n = vasprintf(&str, fmt, args);
	va_end(args);

	if (n == -1)
		return -1;

	for(s = str; *s; ) {
		n = next_nl(s, cols - col);

		ret = dump_line(s, n);
		if (ret)
			break;

		s += n;

		if (*s == '\n') {
			++s;
			++n;
		}
	}

	free(str);
	return ret;
}

int dump_flush(void)
{
	if (dump_outfile)
		fflush(dump_outfile);
	else
		fflush(stdout);
	return 0;
}

