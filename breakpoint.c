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

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backend.h"
#include "breakpoint.h"
#include "debug.h"
#include "library.h"
#include "mtelf.h"
#include "options.h"
#include "report.h"
#include "task.h"
#include "trace.h"

#define HW_BP_SCRATCH_SLOT	0

static unsigned int target_address_hash(unsigned long key)
{
	unsigned int i;
	unsigned int h = 4713;

	union {
		arch_addr_t addr;
		uint16_t v[sizeof(arch_addr_t) / sizeof(uint16_t)];
	} u = { .addr = ARCH_ADDR_T(key) };

	for (i = 0; i < ARRAY_SIZE(u.v); ++i)
		h += (h >> 2) ^ (u.v[i] << 3);

	return h;
}

static int target_address_cmp(unsigned long key1, unsigned long key2)
{
	arch_addr_t addr1 = ARCH_ADDR_T(key1);
	arch_addr_t addr2 = ARCH_ADDR_T(key2);

	return addr1 < addr2 ? 1 : addr1 > addr2 ? -1 : 0;
}

static void enable_sw_breakpoint(struct task *task, struct breakpoint *bp)
{
	static unsigned char break_insn[] = BREAKPOINT_VALUE;

	debug(DEBUG_PROCESS, "pid=%d, addr=%#lx", task->pid, bp->addr);

	copy_from_to_proc(task, bp->addr, break_insn, bp->orig_value, BREAKPOINT_LENGTH);
}

static void disable_sw_breakpoint(struct task *task, const struct breakpoint *bp)
{
	debug(DEBUG_PROCESS, "pid=%d, addr=%lx", task->pid, bp->addr);

	copy_to_proc(task, bp->addr, bp->orig_value, BREAKPOINT_LENGTH);
}

int breakpoint_on_hit(struct task *task, struct breakpoint *bp)
{
	if (bp->on_hit)
		return (bp->on_hit)(task, bp);

	return 0;
}

struct breakpoint *breakpoint_find(struct task *task, arch_addr_t addr)
{
	struct task *leader = task->leader;

	debug(DEBUG_FUNCTION, "pid=%d, addr=%#lx", leader->pid, addr);

	return (struct breakpoint *)dict_find_entry(leader->breakpoints, (unsigned long)addr);
}

#if HW_BREAKPOINTS > 0
static void enable_hw_bp(struct task *task, struct breakpoint *bp)
{
	unsigned int slot = bp->hw_bp_slot;

	assert(bp->type != BP_SW);
	assert(bp->type < BP_HW || task->hw_bp[slot] == NULL);

	task->hw_bp[slot] = bp;

	if (set_hw_bp(task, slot, bp->addr) == -1)
		fatal("set_hw_bp");
}

static void disable_hw_bp(struct task *task, struct breakpoint *bp)
{
	unsigned int slot = bp->hw_bp_slot;

	if (!task->hw_bp[slot])
		return;

	assert(task->hw_bp[slot] == bp);

	if (reset_hw_bp(task, slot) == -1)
		fatal("reset_hw_bp");

	task->hw_bp[slot] = NULL;
}

#if HW_BREAKPOINTS > 1
static void enable_hw_bp_cb(struct task *task, void *data)
{
	enable_hw_bp(task, data);
}

static void disable_hw_bp_cb(struct task *task, void *data)
{
	disable_hw_bp(task, data);
}

static void hw2sw_bp(struct task *leader, struct breakpoint *bp)
{
	each_task(leader, disable_hw_bp_cb, bp);
	bp->hw = 0;
	enable_sw_breakpoint(leader, bp);
}

static int hw_bp_sort(const void *a, const void *b)
{
	const struct breakpoint *p = *(const struct breakpoint **)a;
	const struct breakpoint *q = *(const struct breakpoint **)b;

	if (p->type != q->type)
		return (p->type == BP_HW) ? -1 : 1;

	return (int)(q->hwcnt - p->hwcnt);
}

void reorder_hw_bp(struct task *task)
{
	struct task *leader = task->leader;
	struct list_head *it;
	struct breakpoint *bp_list[leader->hw_bp_num + 1];
	struct breakpoint *bp;
	struct breakpoint **p;
	unsigned long hw_bp_set = 0;
	unsigned int i;
	unsigned int n;

	if (!leader->hw_bp_num)
		return;

	n = 0;
	list_for_each(it, &leader->hw_bp_list) {
		bp = container_of(it, struct breakpoint, link_list);
		if (bp->enabled) {
			assert(n < leader->hw_bp_num);

			bp_list[n++] = bp;
		}
	}

	qsort(bp_list, n, sizeof(*bp_list), hw_bp_sort);

	for(i = 0; i < n; ++i) {
		bp_list[i]->hwcnt = (i < HW_BREAKPOINTS - 1) ? BP_REORDER_THRESHOLD >> (i + 4) : 0;
	}

	if (n > HW_BREAKPOINTS - 1) 
		n = HW_BREAKPOINTS - 1;

	p = bp_list;
	for(i = 0; i < n; ++i) {
		if (bp_list[i]->hw) {
			assert(bp_list[i]->hw_bp_slot != HW_BP_SCRATCH_SLOT);
			assert(bp_list[i]->hw_bp_slot < HW_BREAKPOINTS);
			assert((hw_bp_set & 1 << bp_list[i]->hw_bp_slot) == 0);

			hw_bp_set |= 1 << bp_list[i]->hw_bp_slot;
		}
		else
			*p++ = bp_list[i];
	}
	*p = NULL;

	i = HW_BP_SCRATCH_SLOT + 1;
	for(p = bp_list; (bp = *p); ++p) {
		while(hw_bp_set & (1 << i))
			++i;

		stop_threads(leader);
		disable_sw_breakpoint(leader, bp);

		if (leader->hw_bp[i])
			hw2sw_bp(leader, leader->hw_bp[i]);

		bp->hw_bp_slot = i;
		bp->hw = 1;

		each_task(leader, enable_hw_bp_cb, bp);

		++i;
	}
}

static int insert_hw_bp_slot(struct task *task, struct breakpoint *bp)
{
	struct task *leader = task->leader;
	unsigned int i;

	for(i = HW_BP_SCRATCH_SLOT + 1; i < HW_BREAKPOINTS; ++i) {
		if (!leader->hw_bp[i])
			break;

		if (bp->type == BP_HW && leader->hw_bp[i]->type == BP_AUTO) {
			stop_threads(leader);
			hw2sw_bp(leader, leader->hw_bp[i]);
			break;
		}
	}

	if (i >= HW_BREAKPOINTS)
		return 1;

	bp->hwcnt = 0;
	bp->enabled = 1;
	bp->hw_bp_slot = i;
	bp->hw = 1;

	each_task(leader, enable_hw_bp_cb, bp);

	return 0;
}

void breakpoint_hw_clone(struct task *task)
{
	unsigned int i;
	struct task *leader = task->leader;

	if (leader == task)
		return;

	for(i = HW_BP_SCRATCH_SLOT + 1; i < HW_BREAKPOINTS; ++i) {
		if (!leader->hw_bp[i]) {
			assert(task->hw_bp[i] == NULL);
			continue;
		}

		assert(leader->hw_bp[i]->enabled);
		assert(leader->hw_bp[i]->hw_bp_slot == i);

		enable_hw_bp(task, leader->hw_bp[i]);
	}
}

void breakpoint_hw_destroy(struct task *task)
{
	unsigned int i;

	for(i = 0; i < HW_BREAKPOINTS; ++i)
		task->hw_bp[i] = NULL;

	reset_all_hw_bp(task);
}
#endif

void enable_scratch_hw_bp(struct task *task, struct breakpoint *bp)
{
	if (bp->deleted)
		return;

	if (bp->type != BP_HW_SCRATCH)
		return;

	assert(bp->hw_bp_slot == HW_BP_SCRATCH_SLOT);

	if (task->hw_bp[bp->hw_bp_slot] != bp)
		enable_hw_bp(task, bp);
}

void disable_scratch_hw_bp(struct task *task, struct breakpoint *bp)
{
	if (bp->deleted)
		return;

	if (bp->type != BP_HW_SCRATCH)
		return;

	assert(bp->hw_bp_slot == HW_BP_SCRATCH_SLOT);

	disable_hw_bp(task, bp);
}

static void remove_hw_scratch_bp_cb(struct task *task, void *data)
{
	if (task->hw_bp[HW_BP_SCRATCH_SLOT] == data) {
		assert(task->hw_bp[HW_BP_SCRATCH_SLOT]->hw_bp_slot == HW_BP_SCRATCH_SLOT);

		disable_hw_bp(task, data);
	}
}
#endif

struct breakpoint *breakpoint_new_ext(struct task *task, arch_addr_t addr, struct library_symbol *libsym, int bp_type, size_t ext)
{
	struct task *leader = task->leader;
	struct breakpoint *bp = malloc(sizeof(*bp) + ext);

	if (bp == NULL)
		goto fail1;

	if (options.nohwbp)
		bp_type = BP_SW;

	bp->on_hit = NULL;
	bp->libsym = libsym;
	bp->addr = addr;
	bp->enabled = 0;
	bp->locked = 0;
	bp->deleted = 0;
	bp->ext = ext;
	bp->refcnt = 1;
	bp->count = 0;
#if HW_BREAKPOINTS > 1
	bp->hwcnt = 0;
#endif
	bp->type = bp_type;

	INIT_LIST_HEAD(&bp->link_list);

	switch(bp_type) {
	case BP_HW_SCRATCH:
#if HW_BREAKPOINTS > 0
		bp->hw_bp_slot = HW_BP_SCRATCH_SLOT;
		bp->hw = 1;
		break;
#endif
	case BP_AUTO:
	case BP_HW:
#if HW_BREAKPOINTS > 1
	 	list_add_tail(&bp->link_list, &leader->hw_bp_list);
		leader->hw_bp_num++;
#endif
	case BP_SW:
		memset(bp->orig_value, 0, sizeof(bp->orig_value));
		bp->hw = 0;
	}

	if (dict_add(leader->breakpoints, (unsigned long)addr, bp) < 0) {
		fprintf(stderr, "couldn't enter breakpoint %lx to dictionary\n", addr);
		goto fail2;
	}

	return bp;
fail2:
	free(bp);
fail1:
	return NULL;
}

struct breakpoint *breakpoint_new(struct task *task, arch_addr_t addr, struct library_symbol *libsym, int type)
{
	return breakpoint_new_ext(task, addr, libsym, type, 0);
}

void breakpoint_enable(struct task *task, struct breakpoint *bp)
{
	if (bp->deleted)
		return;

	debug(DEBUG_PROCESS, "pid=%d, addr=%#lx", task->pid, bp->addr);

	if (!bp->enabled) {
#if HW_BREAKPOINTS > 0
		if (bp->type == BP_HW_SCRATCH) {
			bp->enabled = 1;
			return;
		}
#if HW_BREAKPOINTS > 1
		if (bp->type >= BP_HW) {
			if (!insert_hw_bp_slot(task, bp))
				return;
		}
#endif
#endif
		stop_threads(task);
		bp->hw = 0;
		enable_sw_breakpoint(task, bp);
		bp->enabled = 1;
	}
}

void breakpoint_disable(struct task *task, struct breakpoint *bp)
{
	if (bp->deleted)
		return;

	debug(DEBUG_PROCESS, "pid=%d, addr=%#lx", task->pid, bp->addr);

	if (bp->enabled) {
#if HW_BREAKPOINTS > 0
		if (bp->hw) {
			struct task *leader = task->leader;
#if HW_BREAKPOINTS > 1
			if (bp->type != BP_HW_SCRATCH) {
				assert(bp->hw_bp_slot != HW_BP_SCRATCH_SLOT);

				each_task(leader, disable_hw_bp_cb, bp);
				bp->hw = 0;
			}
			else
#endif
			{
				assert(bp->hw_bp_slot == HW_BP_SCRATCH_SLOT);

				each_task(leader, remove_hw_scratch_bp_cb, bp);
			}
			bp->enabled = 0;
			return;
		}
#endif
		stop_threads(task);
		disable_sw_breakpoint(task, bp);
		bp->enabled = 0;
	}
}

struct breakpoint *breakpoint_insert(struct task *task, arch_addr_t addr, struct library_symbol *libsym, int type)
{
	debug(DEBUG_FUNCTION, "pid=%d, addr=%lx, symbol=%s", task->pid, addr, libsym ? libsym->func->name : "NULL");

	if (!addr)
		return NULL;

	struct breakpoint *bp = breakpoint_find(task, addr);
	if (!bp) {
		bp = breakpoint_new(task, addr, libsym, type);
		if (!bp)
			return NULL;
	}

	breakpoint_enable(task, bp);

	return bp;
}

void breakpoint_delete(struct task *task, struct breakpoint *bp)
{
	struct task *leader = task->leader;

	if (bp->deleted)
		return;

	debug(DEBUG_FUNCTION, "pid=%d, addr=%lx", task->pid, bp->addr);

	breakpoint_disable(task, bp);

#if HW_BREAKPOINTS > 1
	if (bp->type >= BP_HW) {
		list_del(&bp->link_list);

		leader->hw_bp_num--;
	}
#endif
	dict_remove_entry(leader->breakpoints, (unsigned long)bp->addr);

	if (options.verbose > 1 && bp->libsym) {
		fprintf(stderr,
			"delete %s breakpoint %s:%s [%#lx] count=%u\n",
				bp->type == BP_SW ? "sw" : "hw",
				bp->libsym->libref->filename,
				bp->libsym->func->demangled_name,
				bp->addr,
				bp->count);
	}

	bp->deleted = 1;
	bp->libsym = NULL;

	breakpoint_put(bp);
}

static int enable_nonlocked_bp_cb(unsigned long key, const void *value, void *data)
{
	struct breakpoint *bp = (struct breakpoint *)value;
	struct task *leader = (struct task *)data;

	debug(DEBUG_FUNCTION, "pid=%d", leader->pid);

	if (!bp->locked)
		breakpoint_enable(leader, bp);

	return 0;
}

void breakpoint_enable_all_nonlocked(struct task *leader)
{
	debug(DEBUG_FUNCTION, "pid=%d", leader->pid);

	if (leader->breakpoints)
		dict_apply_to_all(leader->breakpoints, enable_nonlocked_bp_cb, leader);
}

static int disable_nonlocked_bp_cb(unsigned long key, const void *value, void *data)
{
	struct breakpoint *bp = (struct breakpoint *)value;
	struct task *leader = (struct task *)data;

	debug(DEBUG_FUNCTION, "pid=%d", leader->pid);

	if (!bp->locked)
		breakpoint_disable(leader, bp);

	return 0;
}

void breakpoint_disable_all_nonlocked(struct task *leader)
{
	debug(DEBUG_FUNCTION, "pid=%d", leader->pid);

	if (leader->breakpoints)
		dict_apply_to_all(leader->breakpoints, disable_nonlocked_bp_cb, leader);
	leader->attached = 1;
}

static int enable_bp_cb(unsigned long key, const void *value, void *data)
{
	struct breakpoint *bp = (struct breakpoint *)value;
	struct task *leader = (struct task *)data;

	debug(DEBUG_FUNCTION, "pid=%d", leader->pid);

	breakpoint_enable(leader, bp);

	return 0;
}

void breakpoint_enable_all(struct task *leader)
{
	debug(DEBUG_FUNCTION, "pid=%d", leader->pid);

	if (leader->breakpoints)
		dict_apply_to_all(leader->breakpoints, enable_bp_cb, leader);
}

static int disable_bp_cb(unsigned long key, const void *value, void *data)
{
	struct breakpoint *bp = (struct breakpoint *)value;
	struct task *leader = (struct task *)data;

	debug(DEBUG_FUNCTION, "pid=%d", leader->pid);

	breakpoint_disable(leader, bp);

	return 0;
}

void breakpoint_disable_all(struct task *leader)
{
	debug(DEBUG_FUNCTION, "pid=%d", leader->pid);

	if (leader->breakpoints)
		dict_apply_to_all(leader->breakpoints, disable_bp_cb, leader);
	leader->attached = 1;
}

static int destroy_breakpoint_cb(unsigned long key, const void *value, void *data)
{
	struct breakpoint *bp = (struct breakpoint *)value;
	struct task *leader = (struct task *)data;

	breakpoint_delete(leader, bp);
	return 0;
}

void breakpoint_clear_all(struct task *leader)
{
	if (leader->breakpoints) {
		dict_apply_to_all(leader->breakpoints, &destroy_breakpoint_cb, leader);
		assert(leader->hw_bp_num == 0);
		dict_clear(leader->breakpoints);
		leader->breakpoints = NULL;
	}
}

void breakpoint_setup(struct task *leader)
{
	assert(leader->breakpoints == NULL);

	leader->breakpoints = dict_init(12401, target_address_hash, target_address_cmp);
}

static int clone_single_cb(unsigned long key, const void *value, void *data)
{
	struct breakpoint *bp = (struct breakpoint *)value;
	struct task *new_task = (struct task *)data;
	size_t ext = bp->ext;

	if (bp->deleted)
		return 0;

#if HW_BREAKPOINTS > 0
	if (bp->type == BP_HW_SCRATCH) {
		assert(bp->hw_bp_slot == HW_BP_SCRATCH_SLOT);

		if (bp->hw)
			return 0;
	}
#endif

	struct breakpoint *new_bp = malloc(sizeof(*new_bp) + ext);
	if (!new_bp)
		goto fail1;

	new_bp->libsym = bp->libsym;
	new_bp->addr = bp->addr;
	new_bp->on_hit = bp->on_hit;
	new_bp->enabled = bp->enabled;
	new_bp->locked = bp->locked;
	new_bp->hw = bp->hw;
	new_bp->type = bp->type;
	new_bp->ext = ext;
	new_bp->refcnt = 1;
	new_bp->deleted = 0;
	new_bp->count = 0;

#if HW_BREAKPOINTS > 1
	new_bp->hwcnt = 0;

	if (new_bp->type >= BP_HW) {
		list_add_tail(&new_bp->link_list, &new_task->hw_bp_list);
		new_task->hw_bp_num++;
	}
	else
		INIT_LIST_HEAD(&new_bp->link_list);

	if (new_bp->hw) {
		new_bp->hw_bp_slot = bp->hw_bp_slot;

		assert(new_bp->hw_bp_slot != HW_BP_SCRATCH_SLOT);

		new_task->hw_bp[new_bp->hw_bp_slot] = new_bp;

		if (new_bp->enabled) {
			if (set_hw_bp(new_task, new_bp->hw_bp_slot, new_bp->addr) == -1)
				fatal("set_hw_bp");
		}
	}
	else
#endif
	memcpy(new_bp->orig_value, bp->orig_value, sizeof(bp->orig_value));

	if (ext)
		memcpy((void *)new_bp + ext, (void *)bp + ext, ext);

	if (dict_add(new_task->breakpoints, (unsigned long)new_bp->addr, new_bp) < 0) {
		fprintf(stderr, "couldn't enter breakpoint %lx to dictionary\n", new_bp->addr);
		goto fail2;
	}

	return 0;
fail2:
	free(new_bp);
fail1:
	return -1;
}

int breakpoint_clone_all(struct task *clone, struct task *leader)
{
	return dict_apply_to_all(leader->breakpoints, &clone_single_cb, clone);
}

struct breakpoint *breakpoint_get(struct breakpoint *bp)
{
	if (bp)
		++bp->refcnt;
	return bp;
}

int breakpoint_put(struct breakpoint *bp)
{
	if (bp) {
		assert(bp->refcnt != 0);

		if (--bp->refcnt)
			return 0;

		free(bp);
	}
	return 1;
}

