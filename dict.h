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

#ifndef _INC_DICT_H
#define _INC_DICT_H

struct dict;

struct dict *dict_init(unsigned int size, unsigned int (*key2hash)(unsigned long), int (*key_cmp)(unsigned long, unsigned long));
void dict_clear(struct dict *d);
int dict_add(struct dict *d, unsigned long key, const void *value);
const void *dict_remove_entry(struct dict *d, unsigned long key);
const void *dict_find_entry(struct dict *d, unsigned long key);
int dict_apply_to_all(struct dict *d, int (*func) (unsigned long key, const void *value, void *data), void *data);

#endif

