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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#include "common.h"

void _fatal(const char *file, const char *func, int line, const char *format, ...)
{
	va_list args;
	char *message = NULL;

	va_start(args, format);
	if (vasprintf(&message, format, args) == -1)
		abort();
	va_end(args);

	fprintf(stderr,"%s(%s:%d):\n %s\n", file, func, line, message);

	free(message);
}

char *safe_strncpy(char *dst, const char *src, size_t size)
{
	if (!size)
		return dst;
	dst[--size] = '\0';
	return strncpy(dst, src, size);
}

unsigned long get_val32(void *data, unsigned long index)
{
	return (unsigned long)*(uint32_t *)(data + index * sizeof(uint32_t));
}

unsigned long get_val64(void *data, unsigned long index)
{
	return (unsigned long)*(uint64_t *)(data + index * sizeof(uint64_t));
}

unsigned long find_block(unsigned long (*get_val)(void *data, unsigned long index), void *arr, unsigned long n, unsigned long addr)
{
	unsigned long first, middle, last, val;

	first = 0;
	last = n;

	if (addr < get_val(arr,first))
		return n;

	if (addr > get_val(arr, last - 1))
		return n;

	do {
		middle = (first + last) >> 1;
		val = get_val(arr, middle);

		if (addr < val)
			last = middle;
		else if (addr > val)
			first = middle + 1;
		else
			return middle;

	} while (first < last);

	return n;
}


