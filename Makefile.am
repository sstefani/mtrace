# This file is part of mtrace.
# Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
# 02110-1301 USA

ACLOCAL_AMFLAGS = -I config/m4

SUBDIRS = \
	client \
	sysdeps \
	.

AM_CPPFLAGS += \
	$(libelf_CFLAGS) \
	-DSYSCONFDIR=\"$(sysconfdir)\"

AM_LDFLAGS +=  \
	-Wl,--no-as-needed

mtrace_SOURCES = \
	breakpoint.c \
	common.c \
	debug.c \
	dict.c \
	dwarf.c \
	event.c \
	library.c \
	main.c \
	mtelf.c \
	options.c \
	rbtree.c \
	report.c \
	server.c \
	task.c \
	trace.c

mtrace_LDADD = \
	$(libelf_LIBS) \
	libclient.la \
	sysdeps/libos.la


bin_PROGRAMS = \
	mtrace

noinst_HEADERS = \
	backend.h \
	backtrace.h \
	breakpoint.h \
	common.h \
	debug.h \
	dict.h \
	dwarf.h \
	event.h \
	forward.h \
	library.h \
	list.h \
	main.h \
	mtelf.h \
	mtrace.h \
	options.h \
	rbtree.h \
	report.h \
	task.h \
	thread.h \
	trace.h

dist_doc_DATA = COPYING CREDITS INSTALL README TODO

EXTRA_DIST = 

MAINTAINERCLEANFILES = \
	configure \
	Makefile.in \
	aclocal.m4 \
	config.h.in \
	config.h.in~ \
	config/autoconf/compile \
	config/autoconf/config.guess \
	config/autoconf/config.sub \
	config/autoconf/depcomp \
	config/autoconf/install-sh \
	config/autoconf/ltmain.sh \
	config/autoconf/mdate-sh \
	config/autoconf/missing \
	config/autoconf/texinfo.tex \
	libtool.m4 \
	ltoptions.m4 \
	ltsugar.m4 \
	ltversion.m4 \
	lt~obsolete.m4 \
	$(DIST_ARCHIVES)

maintainer-clean-local:
	-chmod -R a+rw $(distdir)
	-rm -fr $(distdir)
