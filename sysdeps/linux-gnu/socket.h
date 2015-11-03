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

#ifndef _INC_SYSDEPS_LINUX_GNU_SOCKET_H
#define _INC_SYSDEPS_LINUX_GNU_SOCKET_H

#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "common.h"
#include "memtrace.h"

ssize_t safe_read(int fd, void *dest, size_t n);
int connect_to(const char *node, const char *service);
int bind_to(const char *node, const char *service);
int sock_send_msg(int fd, enum mt_operation op, uint32_t pid, uint32_t tid, const void *payload, unsigned int payload_len);
int create_socket_pair(int sv[2]);
int is_named(const char *node);

#endif

