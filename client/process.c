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

#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "binfile.h"
#include "client.h"
#include "common.h"
#include "debug.h"
#include "dump.h"
#include "options.h"
#include "process.h"
#include "rbtree.h"

#define BLOCK_LEAKED	(1 << 0)
#define BLOCK_SCANNED	(1 << 1)
#define BLOCK_IGNORE	(2 << 1)

struct rb_block {
	struct rb_node node;
	unsigned long flags;
	unsigned long addr;
	unsigned long size;
	struct rb_stack *stack_node;
};

struct stack {
	unsigned long refcnt;
	void *addrs;
	uint32_t size;
	uint32_t entries;
	struct rb_sym **syms;
	enum mt_operation operation;
	unsigned int ignore:1;
};

struct rb_stack {
	struct rb_node node;
	struct stack *stack;
	unsigned long refcnt;
	unsigned long leaks;
	unsigned long long n_allocations;
	unsigned long long total_allocations;
	unsigned long long bytes_used;
	unsigned long long bytes_leaked;
	unsigned long long tsc;
	unsigned long long n_mismatched;
	unsigned long long n_badfree;
};

struct map {
	struct list_head list;
	unsigned long offset;
	unsigned long addr;
	unsigned long size;
	unsigned long bias;
	char *filename;
	struct bin_file *binfile;
	unsigned int ignore:1;
};

struct realloc_entry {
	struct list_head list;
	unsigned int pid;
	unsigned long addr;
	unsigned long size;
	unsigned long flags;
	struct rb_stack *stack_node;
};

struct regex_list {
	regex_t re;
	struct regex_list *next;
};

static struct regex_list *regex_ignore_list;
static struct regex_list *regex_ignore_last;

void add_ignore_regex(regex_t *re)
{
	struct regex_list *tmp = malloc(sizeof(*tmp));

	if (!tmp) {
		fprintf(stderr, "%s\n", strerror(errno));
		exit(1);
	}

	tmp->re = *re;
	tmp->next = NULL;

	if (regex_ignore_last)
		regex_ignore_last->next = tmp;
	regex_ignore_last = tmp;

	if (!regex_ignore_list)
		regex_ignore_list = tmp;
}

static const char *str_operation(enum mt_operation operation)
{
	switch(operation) {
	case MT_MALLOC:
		return "malloc";
	case MT_REALLOC_ENTER:
		return "realloc enter";
	case MT_REALLOC:
		return "realloc";
	case MT_REALLOC_DONE:
		return "realloc done";
	case MT_MEMALIGN:
		return "memalign";
	case MT_POSIX_MEMALIGN:
		return "posix_memalign";
	case MT_ALIGNED_ALLOC:
		return "aligned_alloc";
	case MT_VALLOC:
		return "valloc";
	case MT_PVALLOC:
		return "pvalloc";
	case MT_MMAP:
		return "mmap";
	case MT_MMAP64:
		return "mmap64";
	case MT_FREE:
		return "free";
	case MT_MUNMAP:
		return "munmap";
	case MT_NEW:
		return "new";
	case MT_NEW_ARRAY:
		return "new[]";
	case MT_DELETE:
		return "delete";
	case MT_DELETE_ARRAY:
		return "delete[]";
	default:
		break;
	}
	return "unknow operation";
}

static unsigned long get_uint64(void *p)
{
	uint64_t v;

	memcpy(&v, p, sizeof(v));

	return v;
}

static unsigned long get_uint64_swap(void *p)
{
	uint64_t v;

	memcpy(&v, p, sizeof(v));

	return bswap_64(v);
}

static unsigned long get_uint32(void *p)
{
	uint32_t v;

	memcpy(&v, p, sizeof(v));

	return v;
}

static unsigned long get_uint32_swap(void *p)
{
	uint32_t v;

	memcpy(&v, p, sizeof(v));

	return bswap_32(v);
}

static void put_uint64(void *p, unsigned long v)
{
	uint64_t _v = v;

	memcpy(p, &_v, sizeof(_v));
}

static void put_uint64_swap(void *p, unsigned long v)
{
	uint64_t _v = bswap_64(v);

	memcpy(p, &_v, sizeof(_v));
}

static void put_uint32(void *p, unsigned long v)
{
	uint32_t _v = v;

	memcpy(p, &_v, sizeof(_v));
}

static void put_uint32_swap(void *p, unsigned long v)
{
	uint32_t _v = bswap_32(v);

	memcpy(p, &_v, sizeof(_v));
}

static uint16_t val16(uint16_t v)
{
	return v;
}

static uint16_t val16_swap(uint16_t v)
{
	return bswap_16(v);
}

static uint32_t val32(uint32_t v)
{
	return v;
}

static uint32_t val32_swap(uint32_t v)
{
	return bswap_32(v);
}

static uint64_t val64(uint64_t v)
{
	return v;
}

static uint64_t val64_swap(uint64_t v)
{
	return bswap_64(v);
}

static inline int memncmp(void *p1, uint32_t l1, void *p2, uint32_t l2)
{
	int ret = memcmp(p1, p2, (l1 < l2) ? l1 : l2);
	if (ret)
		return ret;
	if (l1 < l2)
		return -1;
	if (l1 > l2)
		return 1;
	return 0;
}

static struct map *locate_map(struct process *process, bfd_vma addr)
{
	struct list_head *it;
	bfd_vma a = (bfd_vma)addr;

	list_for_each(it, &process->map_list) {
		struct map *map = container_of(it, struct map, list);

		if ((a >= map->addr) && (a < map->addr + map->size))
			return map;
	}
	return NULL;
}

static struct map *open_map(struct process *process, bfd_vma addr)
{
	struct map *map = locate_map(process, addr);
	const char *fname;
	char *realpath;
	struct opt_b_t *p;
	static struct opt_b_t opt_b_default = { "", NULL };

	if (!map)
		return NULL;

	if (map->binfile)
		return map;

	if (map->ignore)
		return map;

	p = options.opt_b;
	if (!p)
		p = &opt_b_default;

	do {
		int len = strlen(p->pathname);

		while(len && (p->pathname)[len - 1] == '/')
			--len;

		fname = map->filename;

		do {
			if (asprintf(&realpath, "%.*s%s%s", len, p->pathname, *p->pathname ? "/" : "", fname) == -1) {
				map->ignore = 1;
				return map;
			}

			if (!access(realpath, R_OK))
				map->binfile = bin_file_open(realpath, map->filename);

			free(realpath);

			if (map->binfile)
				return map;

			fname = strchr(fname + 1, '/');
		} while(fname++);

		p = p->next;
	} while(p);

	fprintf(stderr, "file `%s' not found!\n", map->filename);

	map->ignore = 1;

	return map;
}

static struct rb_sym *resolv_address(struct process *process, bfd_vma addr)
{
	struct rb_sym *sym;
	struct map *map = open_map(process, addr);

	if (map) {
		sym = bin_file_lookup(map->binfile, addr, map->bias);
		if (sym)
			return sym;
	}

	sym = malloc(sizeof(*sym));
	if (!sym)
		return NULL;

	sym->addr = addr;
	sym->sym = strdup(map->filename);
	sym->refcnt = 1;
	sym->binfile = NULL;
	sym->si_info = 0;

	return sym;
}

static void stack_resolv(struct process *process, struct stack *stack)
{
	uint32_t i;
	void *addrs;

	stack->syms = malloc(sizeof(*stack->syms) * stack->entries);
	if (!stack->syms)
		return;

	addrs = stack->addrs;

	for(i = 0; i < stack->entries; ++i) {
		unsigned long addr = process->get_ulong(addrs);

		stack->syms[i] = resolv_address(process, addr);

		addrs += process->ptr_size;
	}

	if (regex_ignore_list) {
		for(i = 0; i < stack->entries; ++i) {
			struct regex_list *p;

			for(p = regex_ignore_list; p; p = p->next)
				if (stack->syms[i] && stack->syms[i]->sym && !regexec(&p->re, stack->syms[i]->sym, 0, NULL, 0)) {
					stack->ignore = 1;
					break;
			}

			if (stack->ignore)
				break;
		}
	}
}

static struct rb_stack *stack_get(struct rb_stack *stack_node)
{
	++stack_node->refcnt;
	++stack_node->stack->refcnt;

	return stack_node;
}

static void stack_put(struct rb_stack *stack_node)
{
	struct stack *stack = stack_node->stack;

	if (!--stack_node->refcnt)
		free(stack_node);

	if (!--stack->refcnt) {
		if (stack->syms) {
			unsigned int i;

			for(i = 0; i < stack->entries; ++i)
				bin_file_sym_put(stack->syms[i]);

			free(stack->addrs);
			free(stack->syms);
		}
		free(stack);
	}
}

static struct rb_stack *stack_clone(struct process *process, struct rb_stack *stack_node)
{
	struct rb_root *root = &process->stack_table;
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct rb_stack *this;
	int ret;

	/* Figure out where to put new node */
	while (*new) {
		this = container_of(*new, struct rb_stack, node);

		parent = *new;
		ret = memncmp(stack_node->stack->addrs, stack_node->stack->size, this->stack->addrs, this->stack->size);

		if (ret < 0)
			new = &((*new)->rb_left);
		else
		if (ret > 0)
			new = &((*new)->rb_right);
		else
			return this;
	}

	this = malloc(sizeof(*this));
	if (!this)
		return NULL;

	this->refcnt = 0;
	this->leaks = stack_node->leaks;
	this->n_allocations = stack_node->n_allocations;
	this->n_mismatched = stack_node->n_mismatched;
	this->n_badfree = stack_node->n_badfree;
	this->total_allocations = stack_node->total_allocations;
	this->bytes_used = stack_node->bytes_used;
	this->bytes_leaked = stack_node->bytes_leaked;
	this->tsc = stack_node->tsc;
	this->stack = stack_node->stack;

	stack_get(this);

	/* Add new node and rebalance tree. */
	rb_link_node(&this->node, parent, new);
	rb_insert_color(&this->node, root);

	process->stack_trees++;

	return this;
}

static struct rb_stack *stack_add(struct process *process, void *addrs, uint32_t stack_size, enum mt_operation operation)
{
	struct rb_root *root = &process->stack_table;
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct rb_stack *this;
	struct stack *stack;
	int ret;

	/* Figure out where to put new node */
	while (*new) {
		this = container_of(*new, struct rb_stack, node);

		parent = *new;
		ret = memncmp(addrs, stack_size, this->stack->addrs, this->stack->size);

		if (ret < 0)
			new = &((*new)->rb_left);
		else
		if (ret > 0)
			new = &((*new)->rb_right);
		else {
			assert(this->stack->operation == operation);

			return this;
		}
	}

	this = malloc(sizeof(*this));
	if (!this)
		return NULL;

	stack = malloc(sizeof(*stack));
	if (!stack) {
		free(this);
		return NULL;
	}

	stack->refcnt = 0;
	stack->addrs = malloc(stack_size);
	stack->size = stack_size;
	stack->entries = stack_size / process->ptr_size;
	stack->syms = NULL;
	stack->operation = operation;
	stack->ignore = 0;

	memcpy(stack->addrs, addrs, stack_size);

	this->refcnt = 0;
	this->n_allocations = 0;
	this->n_mismatched = 0;
	this->n_badfree = 0;
	this->total_allocations = 0;
	this->bytes_used = 0;
	this->leaks = 0;
	this->bytes_leaked = 0;
	this->stack = stack;

	stack_get(this);

	stack_resolv(process, stack);

	/* Add new node and rebalance tree. */
	rb_link_node(&this->node, parent, new);
	rb_insert_color(&this->node, root);

	process->stack_trees++;

	return this;
}

static void dump_stack(struct rb_stack *this, int lflag, unsigned long (*get_ulong)(void *), uint8_t ptr_size)
{
	uint32_t i;
	void *addrs;
	struct stack *stack = this->stack;

	if (!stack->syms)
		return;

	for(addrs = stack->addrs, i = 0; i < stack->entries; ++i) {
		if (dump_printf("  [0x%lx]", get_ulong(addrs)))
			return;

		if (!stack->syms[i]) {
			if (dump_printf(" ?") == -1)
				return;
		}
		else {
			if (((lflag && stack->syms[i]->si_info) || !stack->syms[i]->si_info) && stack->syms[i]->binfile) {
				if (dump_printf(" %s", stack->syms[i]->binfile->mapname) == -1)
					return;
			}

			if (stack->syms[i]->sym) {
				if (dump_printf(" %s", stack->syms[i]->sym) == -1)
					return;
			}
		}

		if (dump_printf("\n") == -1)
			return;

		addrs += ptr_size;
	}
}

static void process_dump_collision(struct process *process, struct rb_block *this, unsigned long addr, unsigned long size, enum mt_operation operation)
{
	fprintf(stderr, ">>> block collision pid:%d\n new: %s=%#lx(%lu)\n old: %s=%#lx(%lu)\n",
		process->pid,
		str_operation(operation), addr, size,
		str_operation(this->stack_node->stack->operation), this->addr, this->size
	);
}

static struct rb_block *process_rb_search_range(struct rb_root *root, unsigned long addr, unsigned long size)
{
	struct rb_node *node = root->rb_node;

	if (!size)
		size = 1;

	while (node) {
		struct rb_block *this = container_of(node, struct rb_block, node);

		if ((this->addr <= addr) && (this->addr + this->size > addr))
			return this;

		if (addr < this->addr)
			node = node->rb_left;
		else
			node = node->rb_right;
	}
	return NULL;
}

static struct rb_block *process_rb_search(struct rb_root *root, unsigned long addr)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct rb_block *this = container_of(node, struct rb_block, node);

		if (addr == this->addr)
			return this;

		if (addr < this->addr)
			node = node->rb_left;
		else
			node = node->rb_right;
	}
	return NULL;
}

static void process_release_mem(struct process *process, struct rb_block *block, unsigned int size)
{
	if (block->flags & BLOCK_LEAKED) {
		block->flags &= ~BLOCK_LEAKED;

		block->stack_node->leaks--;
		block->stack_node->bytes_leaked -= block->size;

		process->leaks--;
		process->leaked_bytes -= block->size;
	}

	block->stack_node->bytes_used -= size;

	process->bytes_used -= size;
}

static void process_rb_delete_block(struct process *process, struct rb_block *block)
{
	rb_erase(&block->node, &process->block_table);

	process_release_mem(process, block, block->size);
	process->n_allocations--;

	block->stack_node->n_allocations--;

	stack_put(block->stack_node);

	free(block);
}

static int process_rb_insert_block(struct process *process, unsigned long addr, unsigned long size, struct rb_stack *stack, unsigned long flags, enum mt_operation operation)
{
	struct rb_node **new = &process->block_table.rb_node, *parent = NULL;
	struct rb_block *block;
	unsigned long n;

	n = size;
	if (!n)
		n = 1;

	/* Figure out where to put the new node */
	while (*new) {
		struct rb_block *this = container_of(*new, struct rb_block, node);

		parent = *new;

		if ((addr <= this->addr) && (addr + n > this->addr)) {
			process_dump_collision(process, this, addr, size, operation);

			if (unlikely(options.kill))
				abort();
		}

		if (addr < this->addr)
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
	}

	block = malloc(sizeof(*block));
	if (!block)
		return -1;

	block->addr = addr;
	block->size = size;
	block->flags = flags;
	block->stack_node = stack;
	block->stack_node->n_allocations++;
	block->stack_node->total_allocations++;
	block->stack_node->bytes_used += size;

	stack_get(block->stack_node);

	/* Add new node and rebalance tree. */
	rb_link_node(&block->node, parent, new);
	rb_insert_color(&block->node, &process->block_table);

	process->n_allocations++;

	return 0;
}

static struct map *_process_add_map(struct process *process, unsigned long addr, unsigned long offset, unsigned long size, unsigned long bias, const char *filename, size_t len, struct bin_file *binfile)
{
	struct map *map = malloc(sizeof(*map));

	map->addr = addr;
	map->offset = offset;
	map->size = size;
	map->bias = bias;
	map->filename = malloc(len + 1);
	map->binfile = binfile;
	map->ignore = 0;

	if (binfile)
		bin_file_get(binfile);

	safe_strncpy(map->filename, filename, len + 1);

	if (list_empty(&process->map_list)) {
		free(process->filename);
		process->filename = strdup(map->filename);
	}

	list_add_tail(&map->list, &process->map_list);

	/* fixit: it is now possible that stack_add() produce false matches */

	return map;
}

void process_add_map(struct process *process, void *payload, uint32_t payload_len)
{
	struct mt_map_payload *mt_map = payload;

	uint64_t addr = process->val64(mt_map->addr);
	uint64_t offset = process->val64(mt_map->offset);
	uint64_t size = process->val64(mt_map->size);
	uint64_t bias = process->val64(mt_map->bias);

	_process_add_map(process, addr, offset, size, bias, mt_map->filename, payload_len - sizeof(*mt_map), NULL);
}

static void _process_del_map(struct map *map)
{
	bin_file_put(map->binfile);

	list_del(&map->list);

	free(map->filename);
	free(map);
}

void process_del_map(struct process *process, void *payload, uint32_t payload_len)
{
	struct mt_map_payload *mt_map = payload;
	uint64_t addr = process->val64(mt_map->addr);
	uint64_t offset = process->val64(mt_map->offset);
	uint64_t size = process->val64(mt_map->size);
	struct list_head *it;

	(void)payload_len;

	list_for_each(it, &process->map_list) {
		struct map *map = container_of(it, struct map, list);

		if (map->addr == addr && map->offset == offset && map->size == size) {
			_process_del_map(map);
			return;
		}
	}
	fatal("process_del_map");
}

static void process_init(struct process *process, unsigned int swap_endian, unsigned int is_64bit, unsigned int attached)
{
	if (is_64bit) {
		process->ptr_size = sizeof(uint64_t);
		process->get_ulong = swap_endian ? get_uint64_swap : get_uint64;
		process->put_ulong = swap_endian ? put_uint64_swap : put_uint64;
	}
	else {
		process->ptr_size = sizeof(uint32_t);
		process->get_ulong = swap_endian ? get_uint32_swap : get_uint32;
		process->put_ulong = swap_endian ? put_uint32_swap : put_uint32;
	}

	process->val16 = swap_endian ? val16_swap : val16;
	process->val32 = swap_endian ? val32_swap : val32;
	process->val64 = swap_endian ? val64_swap : val64;

	process->is_64bit = is_64bit;
	process->attached = attached;
	process->swap_endian = swap_endian;
	process->status = MT_PROCESS_RUNNING;
	process->filename = NULL;
}

static void realloc_del(struct realloc_entry *re)
{
	if (re->stack_node)
		stack_put(re->stack_node);
	list_del(&re->list);
	free(re);
}

void process_reset_allocations(struct process *process)
{
	struct rb_block *rbb, *rbb_next;
	struct list_head *it, *next;

	rbtree_postorder_for_each_entry_safe(rbb, rbb_next, &process->block_table, node) {
		--process->n_allocations;
		--rbb->stack_node->n_allocations;
		stack_put(rbb->stack_node);
		free(rbb);
	}

	if (process->n_allocations)
		fatal("invalid allocation count!\n");

	process->block_table = RB_ROOT;

	list_for_each_safe(it, next, &process->realloc_list) {
		struct realloc_entry *re = container_of(it, struct realloc_entry, list);

		realloc_del(re);
	}

	process->total_allocations = 0;
	process->bytes_used = 0;
	process->leaks = 0;
	process->leaked_bytes = 0;
	process->tsc = 0;
}

void process_reset(struct process *process)
{
	struct rb_stack *rbs, *rbs_next;
	struct list_head *it, *next;

	process_reset_allocations(process);

	rbtree_postorder_for_each_entry_safe(rbs, rbs_next, &process->stack_table, node) {
		if (rbs->refcnt != 1)
			fatal("unexpected stack tree ref count!\n");

		stack_put(rbs);
		--process->stack_trees;
	}

	if (process->stack_trees)
		fatal("invalid stack tree count!\n");

	process->stack_table = RB_ROOT;

	list_for_each_safe(it, next, &process->map_list) {
		struct map *map = container_of(it, struct map, list);

		_process_del_map(map);
	}

	free(process->filename);

	process->filename = NULL;
}

static int process_rb_duplicate_block(struct rb_node *node, void *user)
{
	struct rb_block *block = container_of(node, struct rb_block, node);
	struct process *process = user;
	struct rb_stack *stack = stack_clone(process, block->stack_node);

	if (process_rb_insert_block(process, block->addr, block->size, stack, block->flags, block->stack_node->stack->operation))
		return -1;

	process->bytes_used += block->size;

	return 0;
}

void process_duplicate(struct process *process, struct process *copy)
{
	struct list_head *it;

	process_reset(process);
	process_init(process, copy->swap_endian, copy->is_64bit, copy->attached);

	if (!copy)
		return;

	rb_iterate(&copy->block_table, process_rb_duplicate_block, process);

	assert(copy->bytes_used == process->bytes_used);
	assert(copy->n_allocations == process->n_allocations);

	list_for_each(it, &copy->map_list) {
		struct map *map = container_of(it, struct map, list);

		_process_add_map(process, map->addr, map->offset, map->size, map->bias, map->filename, strlen(map->filename), map->binfile);
	}

	process->total_allocations = copy->total_allocations;
	process->tsc = copy->tsc;
}

static int sort_tsc(const struct rb_stack **p, const struct rb_stack **q)
{
	if ((*p)->tsc > (*q)->tsc)
		return -1;
	if ((*p)->tsc < (*q)->tsc)
		return 1;
	return 0;
}

static int _sort_badfree(const struct rb_stack **p, const struct rb_stack **q)
{
	if ((*p)->n_badfree > (*q)->n_badfree)
		return -1;
	if ((*p)->n_badfree < (*q)->n_badfree)
		return 1;
	return 0;
}

static int _sort_mismatched(const struct rb_stack **p, const struct rb_stack **q)
{
	if ((*p)->n_mismatched > (*q)->n_mismatched)
		return -1;
	if ((*p)->n_mismatched < (*q)->n_mismatched)
		return 1;
	return 0;
}

static int sort_badfree(const struct rb_stack **p, const struct rb_stack **q)
{
	int ret;

	ret = _sort_badfree(p, q);
	if (ret)
		return ret;
	return _sort_mismatched(p, q);
}

static int sort_mismatched(const struct rb_stack **p, const struct rb_stack **q)
{
	int ret;

	ret = _sort_mismatched(p, q);
	if (ret)
		return ret;
	return _sort_badfree(p, q);
}

static int sort_usage(const struct rb_stack **p, const struct rb_stack **q)
{
	if ((*p)->bytes_used > (*q)->bytes_used)
		return -1;
	if ((*p)->bytes_used < (*q)->bytes_used)
		return 1;
	return sort_tsc(p, q);
}

static int sort_average(const struct rb_stack **p, const struct rb_stack **q)
{
	double pv, qv;

	if ((*p)->n_allocations)
		pv = (double)(*p)->bytes_used / (*p)->n_allocations;
	else
		pv = 0.0;

	if ((*q)->n_allocations)
		qv = (double)(*q)->bytes_used / (*q)->n_allocations;
	else
		qv = 0.0;

	if (pv > qv)
		return -1;
	if (pv < qv)
		return 1;
	return sort_usage(p, q);
}

static int sort_leaks(const struct rb_stack **p, const struct rb_stack **q)
{
	if ((*p)->leaks > (*q)->leaks)
		return -1;
	if ((*p)->leaks < (*q)->leaks)
		return 1;
	return sort_usage(p, q);
}

static int sort_bytes_leaked(const struct rb_stack **p, const struct rb_stack **q)
{
	if ((*p)->bytes_leaked > (*q)->bytes_leaked)
		return -1;
	if ((*p)->bytes_leaked < (*q)->bytes_leaked)
		return 1;
	return sort_leaks(p, q);
}

static int sort_allocations(const struct rb_stack **p, const struct rb_stack **q)
{
	if ((*p)->n_allocations > (*q)->n_allocations)
		return -1;
	if ((*p)->n_allocations < (*q)->n_allocations)
		return 1;
	return sort_usage(p, q);
}

static int sort_total(const struct rb_stack **p, const struct rb_stack **q)
{
	if ((*p)->total_allocations > (*q)->total_allocations)
		return -1;
	if ((*p)->total_allocations < (*q)->total_allocations)
		return 1;
	return sort_allocations(p, q);
}

static void _process_dump(struct process *process, int (*sortby)(const struct rb_stack **, const struct rb_stack **), int (*skipfunc)(struct rb_stack *), FILE *file, int lflag)
{
	struct rb_stack **arr = NULL;
	unsigned long i;
	void *data;
	unsigned long stack_trees = process->stack_trees;
	unsigned long (*get_ulong)(void *) = process->get_ulong;
	uint8_t ptr_size = process->ptr_size;

	if (dump_init(file) == -1)
		return;

	if (!stack_trees)
		goto skip;

	arr = malloc(sizeof(struct rb_stack *) * stack_trees);
	if (!arr)
		goto skip;

	for(i = 0, data = rb_first(&process->stack_table); data; data = rb_next(data)) {
		struct rb_stack *stack_node = container_of(data, struct rb_stack, node);

		arr[i++] = stack_get(stack_node);
	}

	if (stack_trees != i)
		fatal("invalid stack tree count!\n");

	dump_printf("Process dump %d %s\n", process->pid, process->filename ? process->filename : "<unknown>");

	qsort(arr, stack_trees, sizeof(struct rb_stack *), (void *)sortby);

	if (file == stderr) {
		unsigned long n = stack_trees / 2;
		unsigned long l = stack_trees - 1;

		for(i = 0; i < n; ++i) {
			struct rb_stack *tmp = arr[i];

			arr[i] = arr[l - i];
			arr[l - i] = tmp;
		}
	}

	for(i = 0; i < stack_trees; ++i) {
		struct rb_stack *stack = arr[i];

		if (!skipfunc(stack)) {
			if (stack->n_mismatched || stack->n_badfree) {
				if (dump_printf(
					"Stack (%s):\n"
					" total number of mismatches: %llu\n"
					" total number of bad free: %llu\n",
						str_operation(stack->stack->operation),
						stack->n_mismatched,
						stack->n_badfree
				) == -1)
					break;
			}
			else {
				if (dump_printf(
					"Stack (%s):\n"
					" bytes used: %llu\n"
					" number of open allocations: %llu\n"
					" total number of allocations: %llu\n",
						str_operation(stack->stack->operation),
						stack->bytes_used,
						stack->n_allocations,
						stack->total_allocations
				) == -1)
					break;

				if (stack->leaks) {
					if (dump_printf( " leaked allocations: %lu (%llu bytes)\n", stack->leaks, stack->bytes_leaked) == -1)
						break;
				}
			}

			if (dump_printf(" tsc: %llu\n", stack->tsc) == -1)
				break;

			dump_stack(stack, lflag, get_ulong, ptr_size);
		}
	}

	for(i = 0; i < stack_trees; ++i)
		stack_put(arr[i]);

skip:
	free(arr);
	dump_flush();
	return;
}

static void process_dump(struct process *process, int (*sortby)(const struct rb_stack **, const struct rb_stack **), int (*skipfunc)(struct rb_stack *), const char *outfile, int lflag)
{
	if (!outfile)
		_process_dump(process, sortby, skipfunc, NULL, lflag);
	else {
		FILE *file = fopen(outfile, "w");

		if (!file) {
			fprintf(stderr, "could not open `%s' for output!\n", outfile);
			return;
		}
		_process_dump(process, sortby, skipfunc, file, lflag);

		fclose(file);
	}
}

static int skip_none(struct rb_stack *stack)
{
	(void)stack;

	return 0;
}

static int skip_zero_allocations(struct rb_stack *stack)
{
	return !stack->n_allocations;
}

static int skip_zero_leaks(struct rb_stack *stack)
{
	return !stack->leaks;
}

void process_dump_sort_average(struct process *process,  const char *outfile, int lflag)
{
	process_dump(process, sort_average, skip_zero_allocations, outfile, lflag);
}

void process_dump_sort_usage(struct process *process, const char *outfile, int lflag)
{
	process_dump(process, sort_usage, skip_zero_allocations, outfile, lflag);
}

void process_dump_sort_leaks(struct process *process, const char *outfile, int lflag)
{
	process_dump(process, sort_leaks, skip_zero_leaks, outfile, lflag);
}

void process_dump_sort_bytes_leaked(struct process *process, const char *outfile, int lflag)
{
	process_dump(process, sort_bytes_leaked, skip_zero_leaks, outfile, lflag);
}

void process_dump_sort_allocations(struct process *process, const char *outfile, int lflag)
{
	process_dump(process, sort_allocations, skip_zero_allocations, outfile, lflag);
}

void process_dump_sort_total(struct process *process, const char *outfile, int lflag)
{
	process_dump(process, sort_total, skip_zero_allocations, outfile, lflag);
}

void process_dump_sort_tsc(struct process *process, const char *outfile, int lflag)
{
	process_dump(process, sort_tsc, skip_zero_allocations, outfile, lflag);
}

void process_dump_sort_mismatched(struct process *process, const char *outfile, int lflag)
{
	process_dump(process, sort_mismatched, skip_none, outfile, lflag);
}

void process_dump_sort_badfree(struct process *process, const char *outfile, int lflag)
{
	process_dump(process, sort_badfree, skip_none, outfile, lflag);
}

void process_dump_stacks(struct process *process, const char *outfile, int lflag)
{
	process_dump(process, sort_allocations, skip_none, outfile, lflag);
}

int process_scan(struct process *process, void *leaks, uint32_t payload_len)
{
	unsigned int new = 0;
	unsigned long n = payload_len / process->ptr_size;
	unsigned long i;
	void *new_leaks = leaks;

	for(i = 0; i < n; ++i) {
		struct rb_block *block = process_rb_search(&process->block_table, process->get_ulong(leaks));

		if (block && !(block->flags & BLOCK_LEAKED)) {
			block->flags |= BLOCK_LEAKED;

			block->stack_node->leaks++;
			block->stack_node->bytes_leaked += block->size;

			process->leaks++;
			process->leaked_bytes += block->size;

			memcpy(new_leaks + new * process->ptr_size, leaks, process->ptr_size);
			new++;
		}
		leaks += process->ptr_size;
	}

	dump_init(options.output);
	dump_printf("process %d\n", process->pid);
	dump_printf(" leaks reported: %lu\n", n);
	dump_printf(" new leaks found: %u\n", new);
	dump_printf(" leaked bytes: %llu\n", process->leaked_bytes);

	for(i = 0; i < new; ++i) {
		struct rb_block *block = process_rb_search(&process->block_table, process->get_ulong(new_leaks));

		if (options.verbose > 1) {
			if (dump_printf(" leaked at 0x%08lx (%lu bytes)\n", (unsigned long)block->addr, (unsigned long)block->size) == -1)
				break;
		}

		new_leaks += process->ptr_size;
	}

	dump_printf("leaks total: %lu\n", process->leaks);
	dump_flush();

	if (!options.interactive) {
		process_dump_sortby(process);
		return 1;
	}

	return 0;
}

static inline unsigned long roundup_mask(unsigned long val, unsigned long mask)
{
	return (val + mask) & ~mask;
}

static int is_mmap(enum mt_operation operation)
{
	return operation == MT_MMAP || operation == MT_MMAP64;
}

void process_munmap(struct process *process, struct mt_msg *mt_msg, void *payload)
{
	struct rb_block *block = NULL;
	unsigned long ptr;
	unsigned long size;

	if (!process->tracing)
		return;

	if (process->is_64bit) {
		struct mt_alloc_payload_64 *mt_alloc = payload;

		ptr = process->get_ulong(&mt_alloc->ptr);
		size = process->get_ulong(&mt_alloc->size);
	}
	else {
		struct mt_alloc_payload_32 *mt_alloc = payload;

		ptr = process->get_ulong(&mt_alloc->ptr);
		size = process->get_ulong(&mt_alloc->size);
	}

	do {
		block = process_rb_search_range(&process->block_table, ptr, size);
		if (!block)
			break;

		if (!is_mmap(block->stack_node->stack->operation)) {
			if (unlikely(options.kill)) {
				fprintf(stderr, ">>> block missmatch pid:%d MAP<>MALLOC %#lx\n", process->pid, ptr);
				abort();
			}

			break;
		}

		if (block->addr >= ptr) {
			unsigned off = block->addr - ptr;

			size -= off;
			ptr += off;

			if (size < block->size) {
				process_release_mem(process, block, size);

				block->addr += size;
				block->size -= size;

				break;
			}

			size -= block->size;
			ptr += block->size;

			process_rb_delete_block(process, block);
		}
		else {
			unsigned off = ptr - block->addr;

			if (off + size < block->size) {
				unsigned long new_addr = block->addr + (off + size);
				unsigned long new_size = block->size - (off + size);

				process_release_mem(process, block, block->size - off - new_size);

				block->size = off;

				if (process_rb_insert_block(process, new_addr, new_size, block->stack_node, 0, mt_msg->operation))
					break;

				process->n_allocations++;
				process->total_allocations++;
				process->bytes_used += new_size;

				break;
			}

			process_release_mem(process, block, off);

			block->addr += off;
			block->size -= off;

			size -= block->size;
			ptr += block->size;
		}
	} while(size);
}

static int is_sane(struct rb_block *block, enum mt_operation op)
{
	switch(block->stack_node->stack->operation) {
	case MT_MALLOC:
	case MT_REALLOC:
	case MT_MEMALIGN:
	case MT_POSIX_MEMALIGN:
	case MT_ALIGNED_ALLOC:
	case MT_VALLOC:
	case MT_PVALLOC:
		if (op != MT_FREE && op != MT_REALLOC_ENTER)
			return 0;
		break;
	case MT_NEW:
		if (op != MT_DELETE)
			return 0;
		break;
	case MT_NEW_ARRAY:
		if (op != MT_DELETE_ARRAY)
			return 0;
		break;
	case MT_MMAP:
	case MT_MMAP64:
	default:
		return 0;
	}
	return 1;
}

static void realloc_add(struct process *process, unsigned long pid, unsigned long addr, unsigned long size, unsigned long flags, struct rb_stack *stack_node)
{
	struct realloc_entry *re = malloc(sizeof(*re));

	re->addr = addr;
	re->size = size;
	re->flags = flags;
	re->pid = pid;
	re->stack_node = stack_node;

	if (re->stack_node)
		stack_get(re->stack_node);

	list_add_tail(&re->list, &process->realloc_list);
}

void process_free(struct process *process, struct mt_msg *mt_msg, void *payload)
{
	struct rb_block *block = NULL;
	uint32_t payload_len = mt_msg->payload_len;
	unsigned long ptr;
	unsigned long pid;
	void *stack_data;
	unsigned long stack_size;

	if (!process->tracing)
		return;

	if (process->is_64bit) {
		struct mt_alloc_payload_64 *mt_alloc = payload;

		ptr = process->get_ulong(&mt_alloc->ptr);
		pid = process->get_ulong(&mt_alloc->size);

		stack_data = payload + sizeof(*mt_alloc);
		stack_size = (payload_len - sizeof(*mt_alloc));
	}
	else {
		struct mt_alloc_payload_32 *mt_alloc = payload;

		ptr = process->get_ulong(&mt_alloc->ptr);
		pid = process->get_ulong(&mt_alloc->size);

		stack_data = payload + sizeof(*mt_alloc);
		stack_size = (payload_len - sizeof(*mt_alloc));
	}

	debug(DEBUG_FUNCTION, "ptr=%#lx", ptr);

	if (!ptr)
		return;

	block = process_rb_search(&process->block_table, ptr);
	if (block) {
		if (is_mmap(block->stack_node->stack->operation)) {
			if (unlikely(options.kill)) {
				fprintf(stderr, ">>> block missmatch pid:%d MAP<>MALLOC %#lx\n", process->pid, ptr);
				abort();
			}
		}

		if (stack_size) {
			if (!is_sane(block, mt_msg->operation)) {
				struct rb_stack *stack = stack_add(process, stack_data, stack_size, mt_msg->operation);

				stack->n_mismatched++;
				stack->tsc = process->tsc++;
			}
		}

		if (mt_msg->operation == MT_REALLOC_ENTER)
			realloc_add(process, pid, block->addr, block->size, block->flags, block->stack_node);

		process_rb_delete_block(process, block);
	}
	else {
		if (!process->attached) {
			if (unlikely(options.kill)) {
				fprintf(stderr, ">>> block %#lx not found pid:%d\n", ptr, process->pid);
				abort();
			}

			if (stack_size) {
				struct rb_stack *stack = stack_add(process, stack_data, stack_size, mt_msg->operation);

				stack->n_badfree++;
				stack->tsc = process->tsc++;
			}
		}

		if (mt_msg->operation == MT_REALLOC_ENTER)
			realloc_add(process, pid, 0, 0, 0, NULL);
	}
}

void process_realloc_done(struct process *process, struct mt_msg *mt_msg, void *payload)
{
	unsigned long ptr;
	unsigned int pid;
	struct list_head *it;

	(void)mt_msg;

	if (!process->tracing)
		return;

	if (process->is_64bit) {
		struct mt_alloc_payload_64 *mt_alloc = payload;

		ptr = process->get_ulong(&mt_alloc->ptr);
		pid = process->get_ulong(&mt_alloc->size);
	}
	else {
		struct mt_alloc_payload_32 *mt_alloc = payload;

		ptr = process->get_ulong(&mt_alloc->ptr);
		pid = process->get_ulong(&mt_alloc->size);
	}

	debug(DEBUG_FUNCTION, "ptr=%#lx ", ptr);

	list_for_each(it, &process->realloc_list) {
		struct realloc_entry *re = container_of(it, struct realloc_entry, list);

		if (re->pid == pid) {
			if (!ptr && re->addr)
				process_rb_insert_block(process, re->addr, re->size, re->stack_node, re->flags, re->stack_node->stack->operation);

			realloc_del(re);
			return;
		}
	}

	if (unlikely(options.kill)) {
		fprintf(stderr, ">>> unexpected realloc done pid: %u ptr: %#lx\n", pid, ptr);
		abort();
	}
	return;
}

void process_alloc(struct process *process, struct mt_msg *mt_msg, void *payload)
{
	struct rb_block *block = NULL;
	uint32_t payload_len = mt_msg->payload_len;
	void *stack_data;
	unsigned long stack_size;
	unsigned long ptr;
	unsigned long size;

	debug(DEBUG_FUNCTION, "payload_len=%u", payload_len);

	if (!process->tracing)
		return;

	if (process->is_64bit) {
		struct mt_alloc_payload_64 *mt_alloc = payload;

		ptr = process->get_ulong(&mt_alloc->ptr);
		size = process->get_ulong(&mt_alloc->size);

		stack_data = payload + sizeof(*mt_alloc);
		stack_size = (payload_len - sizeof(*mt_alloc));
	}
	else {
		struct mt_alloc_payload_32 *mt_alloc = payload;

		ptr = process->get_ulong(&mt_alloc->ptr);
		size = process->get_ulong(&mt_alloc->size);

		stack_data = payload + sizeof(*mt_alloc);
		stack_size = (payload_len - sizeof(*mt_alloc));
	}

	debug(DEBUG_FUNCTION, "ptr=%#lx size=%lu stack_size=%lu", ptr, size, stack_size);

	for(;;) {
		block = process_rb_search_range(&process->block_table, ptr, size);
		if (!block)
			break;

		process_dump_collision(process, block, ptr, size, mt_msg->operation);

		if (unlikely(options.kill))
			abort();

		process_rb_delete_block(process, block);
	}

	struct rb_stack *stack = stack_add(process, stack_data, stack_size, mt_msg->operation);

	if (process_rb_insert_block(process, ptr, size, stack, 0, mt_msg->operation)) {
		fprintf(stderr, "process_rb_insert_block failed\n");
		return;
	}

	process->total_allocations++;
	process->bytes_used += size;

	stack->tsc = process->tsc++;
}

void process_reinit(struct process *process, unsigned int swap_endian, unsigned int is_64bit, unsigned int attached)
{
	process_reset(process);
	process_init(process, swap_endian, is_64bit, attached);
}

struct process *process_new(unsigned int pid, unsigned int swap_endian, unsigned int tracing)
{
	struct process *process = malloc(sizeof(*process));

	memset(process, 0, sizeof(*process));

	process->pid = pid;
	process->tracing = tracing;
	process->block_table = RB_ROOT;
	process->stack_table = RB_ROOT;
	INIT_LIST_HEAD(&process->map_list);
	INIT_LIST_HEAD(&process->realloc_list);

	process_init(process, swap_endian, 0, 0);

	return process;
}


void process_dump_sortby(struct process *process)
{
	switch(options.sort_by) {
	case OPT_SORT_AVERAGE:
		_process_dump(process, sort_average, skip_zero_allocations, options.output, options.lflag);
		break;
	case OPT_SORT_BYTES_LEAKED:
		_process_dump(process, sort_bytes_leaked, skip_zero_leaks, options.output, options.lflag);
		break;
	case OPT_SORT_LEAKS:
		_process_dump(process, sort_leaks, skip_zero_leaks, options.output, options.lflag);
		break;
	case OPT_SORT_STACKS:
		_process_dump(process, sort_allocations, skip_none, options.output, options.lflag);
		break;
	case OPT_SORT_TOTAL:
		_process_dump(process, sort_total, skip_none, options.output, options.lflag);
		break;
	case OPT_SORT_TSC:
		_process_dump(process, sort_tsc, skip_zero_allocations, options.output, options.lflag);
		break;
	case OPT_SORT_USAGE:
		_process_dump(process, sort_usage, skip_zero_allocations, options.output, options.lflag);
		break;
	case OPT_SORT_MISMATCHED:
		_process_dump(process, sort_mismatched, skip_none, options.output, options.lflag);
		break;
	case OPT_SORT_BADFREE:
		_process_dump(process, sort_badfree, skip_none, options.output, options.lflag);
		break;
	default:
		_process_dump(process, sort_allocations, skip_zero_allocations, options.output, options.lflag);
		break;
	}
}

int process_exit(struct process *process)
{
	process_set_status(process, MT_PROCESS_EXIT);

	if (!options.interactive) {
		process_dump_sortby(process);
		return 1;
	}

	fprintf(stderr, "+++ process %d exited\n", process->pid);
	return 0;
}

void process_about_exit(struct process *process)
{
	process_set_status(process, MT_PROCESS_EXITING);

	if (options.auto_scan)
		process_leaks_scan(process, SCAN_ALL);

	client_send_msg(process, MT_ABOUT_EXIT, NULL, 0);
}

int process_detach(struct process *process)
{
	int ret = 0;

	process_set_status(process, MT_PROCESS_DETACH);

	if (options.auto_scan) {
		process_leaks_scan(process, SCAN_ALL);
	}
	else {
		if (!options.interactive) {
			process_dump_sortby(process);
			ret = 1;
		}
	}

	client_send_msg(process, MT_DETACH, NULL, 0);

	return ret;
}

void process_set_status(struct process *process, enum process_status status)
{
	process->status = status;
}

static void process_block_foreach(struct process *process, void (*func)(struct rb_block *, void *), void *user)
{
	struct rb_node *data;

	for(data = rb_first(&process->block_table); data; data = rb_next(data))
		func(container_of(data, struct rb_block, node), user);
}

static const char *process_get_status(struct process *process)
{
	const char *str;

	switch(process->status) {
	case MT_PROCESS_RUNNING:
		str = "running";
		break;
	case MT_PROCESS_EXIT:
		str = "exited";
		break;
	case MT_PROCESS_EXITING:
		str = "exiting";
		break;
	case MT_PROCESS_IGNORE:
		str = "ignored";
		break;
	case MT_PROCESS_DETACH:
		str = "detached";
		break;
	default:
		str = "unknown";
		break;
	}
	return str;
}

void process_status(struct process *process)
{
	printf(
		"process %d status\n"
		" bytes used: %lu\n"
		" number of open allocations: %lu\n"
		" total number of allocations: %lu\n"
		" average allocation: %f bytes\n"
		" number of leaks: %lu\n"
		" number of leaked bytes: %llu\n"
		" status: %s\n",
		process->pid,
		process->bytes_used,
		process->n_allocations,
		process->total_allocations,
		process->n_allocations ? (double)process->bytes_used / process->n_allocations : 0.0,
		process->leaks,
		process->leaked_bytes,
		process_get_status(process)
	);
}

struct block_helper {
	struct process *process;
	unsigned int	len;
	unsigned long	mask;
	unsigned long	fmask;
	unsigned long	fmode;
	void *		data;
};

static void set_block(struct rb_block *block, void *data)
{
	struct block_helper *bh = data;
	unsigned long addr;

	if (block->stack_node->stack->ignore)
		return;

	if ((block->flags & bh->fmask) != 0)
		return;

	if ((block->flags & bh->fmode) != bh->fmode)
		return;

	block->flags |= BLOCK_SCANNED;

	for (addr = (unsigned long) block->addr; addr & bh->mask; bh->mask >>= 1)
		;

	bh->process->put_ulong(bh->data, block->addr);
	bh->data += bh->process->ptr_size;

	bh->len++;
}

unsigned long process_leaks_scan(struct process *process, int mode)
{
	struct mt_scan_payload *payload;
	unsigned int payload_len;
	unsigned long n;
	unsigned long mask;
	unsigned long fmask;
	unsigned long fmode;

	if (!process->n_allocations)
		return 0;

	switch(mode) {
	case SCAN_ALL:
		fmask = 0;
		fmode = 0;
		break;
	case SCAN_NEW:
		fmask = BLOCK_SCANNED;
		fmode = 0;
		break;
	case SCAN_LEAK:
		fmask = 0;
		fmode = BLOCK_LEAKED;
		break;
	default:
		return 0;
	}

	payload_len = sizeof(*payload) + process->n_allocations * process->ptr_size;

	payload = malloc(payload_len);
	if (!payload) {
		fprintf(stderr, "leak scan: out of memory!\n");
		return 0;
	}
	memset(payload, 0, payload_len);

	struct block_helper bh = { .process = process, .len = 0, .mask = ~0, .data = payload->data, .fmask = fmask | BLOCK_IGNORE, .fmode = fmode };

	process_block_foreach(process, set_block, &bh);

	n = bh.len;
	mask = bh.mask;

	if (dump_init(options.output) != -1) {
		dump_printf("process %d scanning %lu allocations\n", process->pid, n);
		dump_flush();
	}

	payload_len = sizeof(*payload) + n * process->ptr_size;

	payload->ptr_size = process->val32(process->ptr_size);
	payload->mask = process->val64(mask);

	client_send_msg(process, MT_SCAN, payload, payload_len);

	free(payload);

	return n;
}

