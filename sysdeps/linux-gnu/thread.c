/*
 * phtread thread wrapper
 *
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
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include "thread.h"

struct thread {
	pthread_t thread;
	int running;
	pthread_attr_t attr;
	void *arg;
	void *(*start_routine)(void *);
};

struct thread *thread_new(void)
{
	int ret;

	struct thread *thread = malloc(sizeof(*thread));

	if (!thread)
		return NULL;

	thread->running = 0;

	ret = pthread_attr_init(&thread->attr);
	if (ret) {
		fprintf(stderr, "pthread_attr_init failed: %s\n", strerror(ret));
		goto fail1;
	}

	ret = pthread_attr_setdetachstate(&thread->attr, PTHREAD_CREATE_JOINABLE);
	if (ret) {
		fprintf(stderr, "pthread_attr_setdetachstate failed: %s\n", strerror(ret));
		goto fail2;
	}

	ret = pthread_attr_setinheritsched(&thread->attr, PTHREAD_EXPLICIT_SCHED);
	if (ret) {
		fprintf(stderr, "pthread_attr_setinheritsched failed: %s\n", strerror(ret));
		goto fail2;
	}

	return thread;
fail2:
	pthread_attr_destroy(&thread->attr);
fail1:
	free(thread);
	return NULL;
}

void thread_remove(struct thread *thread)
{
	thread_join(thread);

	pthread_attr_destroy(&thread->attr);

	free(thread);
}

static void *thread_wrapper(void *instance)
{
	struct thread *thread = instance;
	void *ret;

	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	ret = thread->start_routine(thread->arg);

	pthread_exit(ret);

	return ret;
}

int thread_start(struct thread *thread, void *(*start_routine)(void *), void *arg)
{
	int	ret;

	if (thread->running)
		return -1;

	thread->start_routine = start_routine;
	thread->arg = arg;

	ret = pthread_create(&thread->thread, &thread->attr, thread_wrapper, thread);

	if (!ret)
		thread->running = 1;

	return ret;
}

void thread_join(struct thread *thread)
{
	if (thread->running) {
		pthread_join(thread->thread, 0);

		thread->running = 0;
	}
}

void thread_enable_cancel(void)
{
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
}

void thread_disable_cancel(void)
{
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
}

void thread_cancel(struct thread *thread)
{
	if (thread->running)
		pthread_cancel(thread->thread);
}

