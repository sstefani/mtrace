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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>

#include "common.h"
#include "dict.h"
#include "list.h"

struct dict_entry {
	struct list_head list;
	unsigned long key;
	const void *value;
};

struct dict {
	unsigned int size;
	unsigned int (*key2hash)(unsigned long);
	int (*key_cmp)(unsigned long, unsigned long);
	struct list_head buckets[0];
};

struct dict *dict_init(unsigned int size, unsigned int (*key2hash)(unsigned long), int (*key_cmp)(unsigned long, unsigned long))
{
	struct dict *d;
	unsigned int i;

	d = malloc(sizeof(*d) + sizeof(d->buckets[0]) * size);

	d->size = size;
	d->key2hash = key2hash;
	d->key_cmp = key_cmp;

	for (i = 0; i < d->size; i++)
		INIT_LIST_HEAD(&d->buckets[i]);

	return d;
}

void dict_clear(struct dict *d)
{
	unsigned int i;
	struct list_head *it, *next;

	for (i = 0; i < d->size; i++) {
		list_for_each_safe(it, next, &d->buckets[i]) {
			struct dict_entry *entry = container_of(it, struct dict_entry, list);

			free(entry);
		}
	}
	free(d);
}

static struct dict_entry *_dict_find_entry(struct dict *d, unsigned long key, unsigned int hash)
{
	struct list_head *it;

	list_for_each(it, &d->buckets[hash]) {
		struct dict_entry *entry = container_of(it, struct dict_entry, list);

		if (!d->key_cmp(key, entry->key))
			return entry;
	}
	return NULL;
}

int dict_add(struct dict *d, unsigned long key, const void *value)
{
	struct dict_entry *newentry;
	unsigned int hash = d->key2hash(key) % d->size;

	if (_dict_find_entry(d, key, hash))
		return -1;

	newentry = malloc(sizeof(*newentry));

	newentry->key = key;
	newentry->value = value;

	INIT_LIST_HEAD(&newentry->list);

	list_add(&newentry->list, &d->buckets[hash]);

	return 0;
}

const void *dict_remove_entry(struct dict *d, unsigned long key)
{
	unsigned int hash = d->key2hash(key) % d->size;
	struct dict_entry *entry = _dict_find_entry(d, key, hash);

	if (entry) {
		const void *value = entry->value;

		list_del(&entry->list);
		free(entry);

		return value;
	}
	return NULL;
}

const void *dict_find_entry(struct dict *d, unsigned long key)
{
	unsigned int hash = d->key2hash(key) % d->size;
	struct dict_entry *entry = _dict_find_entry(d, key, hash);

	return entry ? entry->value : NULL;
}

int dict_apply_to_all(struct dict *d, int (*func)(unsigned long key, const void *value, void *data), void *data)
{
	unsigned int i;

	for (i = 0; i < d->size; i++) {
		struct list_head *it, *next;

		list_for_each_safe(it, next, &d->buckets[i]) {
			struct dict_entry *entry = container_of(it, struct dict_entry, list);

			if (func(entry->key, entry->value, data))
				return -1;
		}
	}
	return 0;
}

