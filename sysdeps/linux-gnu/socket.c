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

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <byteswap.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include "common.h"
#include "socket.h"
#include "memtrace.h"

struct sock_u_descr {
	struct sockaddr_un addr;
	socklen_t addrlen;
};

static const int const_int_1 = 1;

ssize_t safe_read(int fd, void *dest, size_t n)
{
	int off = 0;
	ssize_t ret;

	for(;;) {
		ret = TEMP_FAILURE_RETRY(read(fd, dest + off, n));

		if (ret <= 0)
			return ret;

		if ((size_t)ret >= n)
			break;

		off += ret;
		n -= ret;
	}
	return off + n;
}

int sock_send_msg(int fd, enum mt_operation op, uint32_t pid, const void *payload, unsigned int payload_len)
{
	struct mt_msg mt_msg;
	struct iovec	io[2];
	struct msghdr	msghdr;
	int ret;

	if (fd == -1)
		return -1;

	msghdr.msg_name = NULL;
	msghdr.msg_namelen = 0;
	msghdr.msg_iov = io;
	msghdr.msg_iovlen = 1;
	msghdr.msg_control = 0;
	msghdr.msg_controllen = 0;
	msghdr.msg_flags = 0;

	io[0].iov_base = &mt_msg;
	io[0].iov_len = sizeof(mt_msg);

	if (payload_len) {
		io[msghdr.msg_iovlen].iov_base = (void *)payload;
		io[msghdr.msg_iovlen].iov_len = payload_len;

		msghdr.msg_iovlen++;
	}

	mt_msg.operation = op;

	if (op > 0xff) {
		mt_msg.pid = bswap_32(pid);
		mt_msg.payload_len = bswap_32(payload_len);
	}
	else {
		mt_msg.pid = pid;
		mt_msg.payload_len = payload_len;
	}

	ret = TEMP_FAILURE_RETRY(sendmsg(fd, &msghdr, MSG_NOSIGNAL));

	if ((size_t)ret != sizeof(mt_msg) + payload_len)
		return -1;

	return ret;
}

static int sock_unix(const char *path, struct sock_u_descr *descr, int create)
{
	struct stat statbuf;

	if (stat(path, &statbuf) >= 0) {
		if (!S_ISSOCK(statbuf.st_mode))
			return -1;

		if (create)
			unlink(path);
	}

	descr->addr.sun_family = AF_UNIX;
	safe_strncpy(descr->addr.sun_path, path, sizeof(descr->addr.sun_path));
	descr->addrlen = sizeof(descr->addr.sun_family) + strlen(descr->addr.sun_path);

	return socket(PF_UNIX, SOCK_STREAM, 0);
}

static struct addrinfo *sock_addr(const char *node, const char *service, int flags)
{
	struct addrinfo *result;
	struct addrinfo hints;
	int ret;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = flags;
	hints.ai_protocol = 0;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	ret = getaddrinfo(node, service, &hints, &result);
	if (ret != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
		return NULL;
	}

	return result;
}

int connect_to(const char *node, const char *service)
{
	int sfd;

	if (*node == '/' || *node == '.') {
		struct sock_u_descr descr;

		sfd = sock_unix(node, &descr, 0);
		if (sfd == -1)
			return -1;

		if (connect(sfd, &descr.addr, descr.addrlen) == -1) {
			close(sfd);
			return -1;
		}
	}
	else {
		struct addrinfo *rp;

		for (rp = sock_addr(node, service, 0); rp != NULL; rp = rp->ai_next) {
			sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
			if (sfd == -1)
				continue;

			if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
				break;

			close(sfd);
		}

		if (!rp)
			return -1;
	}
	return sfd;
}

int is_named(const char *node)
{
	return node && (*node == '/' || *node == '.');
}

int bind_to(const char *node, const char *service)
{
	int sfd;

	if (is_named(node)) {
		struct sock_u_descr descr;

		sfd = sock_unix(node, &descr, 1);
		if (sfd == -1)
			return -1;

		if (bind(sfd, &descr.addr, descr.addrlen) < 0) {
			close(sfd);
			return -1;
		}
	}
	else {
		struct addrinfo *rp;
		int size = 10 * 1024 * 1024;
		static const int one = 1;

		for (rp = sock_addr(node, service, AI_PASSIVE); rp != NULL; rp = rp->ai_next) {
			sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
			if (sfd == -1)
				continue;

			if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &const_int_1, sizeof(const_int_1)))
				fatal("setsockopt (%s)", strerror(errno));

			if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
				break;

			close(sfd);
		}

		if (!rp)
			return -1;

		if (setsockopt(sfd, SOL_TCP, TCP_NODELAY, &one, sizeof(one)) == -1)
			fatal("TCP_NODELAY: %s\n", strerror(errno));

		if (setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == -1)
			fatal("SO_SNDBUF: %s\n", strerror(errno));
	}

	return sfd;
}

int create_socket_pair(int sv[2])
{
	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, sv) == -1) {
		perror("socketpair");
		return -1;
	}
	return 0;
}

