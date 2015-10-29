# -*- Autoconf -*-
# This file is part of mtrace.
# Copyright (C) 2015 Stefani Seibold <stefani@seibold.net>
# Copyright (C) 2010,2013 Petr Machata, Red Hat Inc.
# Copyright (C) 2010,2011 Joe Damato
# Copyright (C) 2010 Marc Kleine-Budde
# Copyright (C) 2010 Zachary T Welch
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

# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.65)

AC_INIT([mtrace],[0.3],[stefani@seibold.net])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR(main.c)
AC_CONFIG_MACRO_DIR([config/m4])
AC_CONFIG_AUX_DIR([config/autoconf])
AC_CANONICAL_BUILD
AC_CANONICAL_HOST

case "${host_os}" in
    linux-gnu*) HOST_OS="linux-gnu" ;;
    linux-uclibc*) HOST_OS="linux-gnu" ;;
    *)		AC_MSG_ERROR([unkown host-os ${host_os}]) ;;
esac
AC_SUBST(HOST_OS)

case "${host_cpu}" in
    arm*|sa110)		HOST_CPU="arm" ;;
    cris*)		HOST_CPU="cris" ;;
    mips*)		HOST_CPU="mips" ;;
    powerpc|powerpc64)	HOST_CPU="ppc" ;;
    sun4u|sparc64)	HOST_CPU="sparc" ;;
    s390x)		HOST_CPU="s390" ;;
    i?86|x86_64)	HOST_CPU="x86" ;;
    *)			HOST_CPU="${host_cpu}" ;;
esac
AC_SUBST(HOST_CPU)

# Checks for programs.
AC_PROG_CC
LT_INIT
# libtool-2:  LT_INIT()
AM_INIT_AUTOMAKE([foreign no-exeext dist-bzip2])
AM_MAINTAINER_MODE

AC_MSG_CHECKING([whether to disable client support])
AC_ARG_ENABLE(client,
    AC_MSG_WARN( hallo)
    AS_HELP_STRING([--disable-client], [disable client @<:@default=no@:>@]),
	[case "$enableval" in
	n | no) CONFIG_DISABLE_CLIENT=yes ;;
        *) CONFIG_DISABLE_CLIENT=no ;;
    esac],
    [CONFIG_DISABLE_CLIENT=no])
AC_MSG_RESULT([${CONFIG_DISABLE_CLIENT}])
if test "${CONFIG_DISABLE_CLIENT}" = "yes"; then
	AC_DEFINE(DISABLE_CLIENT, 1, [disable client])
fi
AM_CONDITIONAL(DISABLE_CLIENT, [test "${CONFIG_DISABLE_CLIENT}" = "yes"])


AC_ARG_WITH([libelf],
  AS_HELP_STRING([--with-libelf], [Prefix of libelf headers/library]),
  [case "${withval}" in
  (no)
    AC_MSG_ERROR([*** libelf is a required dependency])
    ;;
  (yes)
    AC_MSG_ERROR([*** --with-libelf requires you to specify a path])
    ;;
  (*)
    AM_CPPFLAGS="${AM_CPPFLAGS} -I${withval}/include"
    AM_LDFLAGS="${AM_LDFLAGS} -L${withval}/lib"
    libelf_LD_LIBRARY_PATH="${withval}/lib"
    ;;
esac],[])

# Checks for libraries.

saved_CPPFLAGS="${CPPFLAGS}"
saved_LDFLAGS="${LDFLAGS}"
CPPFLAGS="${CPPFLAGS} ${AM_CPPFLAGS}"
LDFLAGS="${LDFLAGS} ${AM_LDFLAGS}"

# libelf
AC_CHECK_HEADERS([elf.h gelf.h],,
	[AC_MSG_ERROR([*** elf.h or gelf.h not found on your system])]
)
AC_CHECK_LIB([elf], [elf_begin],,
	[AC_MSG_ERROR([*** libelf not found on your system])]
)
CPPFLAGS="${saved_CPPFLAGS}"
LDFLAGS="${saved_LDFLAGS}"

# libreadline
if test "${CONFIG_DISABLE_CLIENT}" != "yes"; then
	AC_CHECK_HEADERS([readline/readline.h],,
		[AC_MSG_ERROR([*** readline.h not found on your system])]
	)
	AC_CHECK_LIB([readline], [rl_callback_read_char],,
		[AC_MSG_ERROR([*** libreadline not found on your system])]
	)
fi

# libbfd
if test "${CONFIG_DISABLE_CLIENT}" != "yes"; then
	AC_CHECK_HEADERS([bfd.h],,
		[AC_MSG_ERROR([*** bfd.h not found on your system])]
	)
	AC_CHECK_LIB([bfd], [bfd_openr],,
		[AC_MSG_ERROR([*** libbfd not found on your system])]
	)
fi

# libpthread
AC_CHECK_HEADERS([pthread.h],,
	[AC_MSG_ERROR([*** pthread.h not found on your system])]
)
AC_CHECK_LIB([pthread], [pthread_create],,
	[AC_MSG_ERROR([*** libpthread not found on your system])]
)

# libdl
AC_CHECK_HEADERS([dlfcn.h],,
	[AC_MSG_ERROR([*** dlfcn.h not found on your system])]
)
AC_CHECK_LIB([dl], [dladdr],,
	[AC_MSG_ERROR([*** libdl not found on your system])]
)

# libtermcap
#AC_CHECK_HEADERS([termcap.h],,
#	[AC_MSG_ERROR([*** termcap.h not found on your system])]
#)
AC_CHECK_LIB([termcap], [tgetflag],,
)


dnl Check security_get_boolean_active availability.
AC_CHECK_HEADERS(selinux/selinux.h)
AC_CHECK_LIB(selinux, security_get_boolean_active)

saved_CPPFLAGS="${CPPFLAGS}"
saved_LDFLAGS="${LDFLAGS}"
CPPFLAGS="${CPPFLAGS} ${AM_CPPFLAGS}"
LDFLAGS="${LDFLAGS} ${AM_LDFLAGS}"

# HAVE_ELF_C_READ_MMAP
AC_MSG_CHECKING([whether elf_begin accepts ELF_C_READ_MMAP])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <gelf.h>]], [[
int main () {
	Elf *elf = elf_begin(4, ELF_C_READ_MMAP, 0);
	return 0;
}
	]])],[
	AC_DEFINE([HAVE_ELF_C_READ_MMAP], [1], [we have read mmap support])
	AC_MSG_RESULT([yes])],[
	AC_MSG_RESULT([no])])
CPPFLAGS="${saved_CPPFLAGS}"
LDFLAGS="${saved_LDFLAGS}"

saved_CFLAGS="${CFLAGS}"
CFLAGS="${CFLAGS} -Wall -Werror"
AC_MSG_CHECKING([whether elf_hash takes a char* argument])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <libelf.h>]], [[
	(void) elf_hash("name");
	]])],
	[AC_DEFINE([ELF_HASH_TAKES_CHARP], [1],
		[elf_hash() takes char* (as opposed to unsigned char *)])
	 AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])])
CFLAGS="${saved_CFLAGS}"
CPPFLAGS="${saved_CPPFLAGS}"
LDFLAGS="${saved_LDFLAGS}"

AM_CPPFLAGS=" \
	${AM_CPPFLAGS} \
	-I\$(top_srcdir)/client \
	-I\$(top_srcdir)/sysdeps/${HOST_OS}/${HOST_CPU} \
	-I\$(top_srcdir)/sysdeps/${HOST_OS} \
	-I\$(top_srcdir)/sysdeps \
	-I\$(top_srcdir) \
"

# Checks for header files.
AC_CHECK_HEADERS([ \
	fcntl.h \
	limits.h \
	stddef.h \
	stdint.h \
	stdlib.h \
	string.h \
	sys/ioctl.h \
	sys/param.h \
	sys/time.h \
	unistd.h \
])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_SIZEOF([long])


# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_CHECK_FUNCS([ \
	alarm \
	atexit \
	getcwd \
	gettimeofday \
	memset \
	mkdir \
	rmdir \
	strchr \
	strdup \
	strerror \
	strtol \
	strtoul \
	process_vm_readv \
])


#
# Debugging
#
AC_MSG_CHECKING([whether to enable debugging])
AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug], [enable debugging @<:@default=no@:>@]),
	[case "$enableval" in
	y | yes) CONFIG_DEBUG=yes ;;
        *) CONFIG_DEBUG=no ;;
    esac],
    [CONFIG_DEBUG=no])
AC_MSG_RESULT([${CONFIG_DEBUG}])
if test "${CONFIG_DEBUG}" = "yes"; then
    AC_DEFINE(DEBUG, 1, [debugging])
else
    AM_CFLAGS="${AM_CFLAGS} -DNDEBUG"
fi

# Ignore the compiler's warnings at your own risk.
AM_CFLAGS="${AM_CFLAGS} -Wall -Wsign-compare -Wfloat-equal -Wformat-security -rdynamic"
AC_ARG_ENABLE([werror],
    AS_HELP_STRING([--disable-werror], [disable use of -Werror]),
    [enable_werror=$enableval], [enable_werror=yes])
if test x$enable_werror = xyes; then
    AM_CFLAGS="${AM_CFLAGS} -Werror"
fi

AC_SUBST(AM_CPPFLAGS)
AC_SUBST(AM_CFLAGS)
AC_SUBST(AM_LDFLAGS)
AC_SUBST(libelf_LD_LIBRARY_PATH)

AC_CONFIG_FILES([
	Makefile
	client/Makefile
	sysdeps/Makefile
	sysdeps/linux-gnu/Makefile
	sysdeps/linux-gnu/x86/Makefile
	sysdeps/linux-gnu/ppc/Makefile
	sysdeps/linux-gnu/arm/Makefile
])
AC_OUTPUT
