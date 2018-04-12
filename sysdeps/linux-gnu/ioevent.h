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

#ifndef _INC_SYSDEPS_LINUX_GNU_IOEVENT_H
#define _INC_SYSDEPS_LINUX_GNU_IOEVENT_H

typedef int (*ioevent_func)(void);

int ioevent_add_input(int fd, ioevent_func func);
int ioevent_del_input(int fd);
int ioevent_watch(int timeout);
int ioevent_wait_input(int fd, int timeout);
ioevent_func ioevent_set_input_func(int fd, ioevent_func func);

#endif

