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

#ifndef _INC_COMMON_H
#define _INC_COMMON_H

#include <config.h>

#include <sys/types.h>
#include <sys/time.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof (x) / sizeof *(x))
#endif

/**
 * Macro to convert a constant number value into a string constant
 */
#define XSTR(x)	#x
#define STR(x)	XSTR(x)

#ifndef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE, MEMBER) __compiler_offsetof(TYPE, MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
#endif

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})


#if 1
#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)
#else
#define likely(x)	(x)
#define unlikely(x)	(x)
#endif

#define	fatal(fmt...)	_fatal(__FILE__,__PRETTY_FUNCTION__,__LINE__ , ##fmt),abort()

void _fatal(const char *file, const char *func, int line, const char *format, ...) __attribute__ ((format (printf, 4, 5)));;

char *safe_strncpy(char *dst, const char *src, size_t size);

unsigned long get_val32(void *data, unsigned long index);

unsigned long get_val64(void *data, unsigned long index);

unsigned long find_block(unsigned long (*get_val)(void *data, unsigned long index), void *arr, unsigned long n, unsigned long addr);

#endif

