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

#ifndef _INC_MAIN_H
#define _INC_MAIN_H

#include <sys/types.h>

#include "timer.h"

void mtrace_request_exit(void);

struct mt_timer stop_time;
struct mt_timer sw_bp_time;
struct mt_timer hw_bp_time;
struct mt_timer backtrace_time;
struct mt_timer reorder_time;
struct mt_timer report_in_time;
struct mt_timer report_out_time;
struct mt_timer skip_bp_time;

pid_t mtrace_pid;
#endif

