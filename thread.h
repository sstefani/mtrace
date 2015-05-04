/*
 * This file is part of mtrace.
 * Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
 *
 * This work was sponsored by Rohde & Schwarz GmbH & Co. KG, Munich.
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

#ifndef _INC_THREAD_H
#define _INC_THREAD_H

struct thread;

/* create a thread object */
struct thread *thread_new(void);

/* remove a thread object (wait if the thread is still running */
void thread_remove(struct thread *thread);

/* start a thread with the given start routine and the pass the give arg pointer */
int thread_start(struct thread *thread, void *(*start_routine)(void *), void *arg);

/* wait for termination of the thread */
void thread_join(struct thread *thread);

/* enable cancelation of the current running thread */
void thread_enable_cancel(void);

/* disable cancelation of the current running thread */
void thread_disable_cancel(void);

/* cancel thread */
void thread_cancel(struct thread *thread);

#endif

