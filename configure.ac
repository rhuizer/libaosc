# Dedicated to Kanna Ishihara.
#
# Copyright (C) 2009 Ronald Huizer
#
# This library is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2 of
# the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
# MA 02110-1301, USA.

AC_PREREQ(2.59)
AC_INIT([libaosc], [1.0.2], [scrippie@xs4all.nl])

# Host settings
#
# build:        system we're building on
# host:         system we're building for,
# target:       system the program we're building will build for
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

# Initialize the automake subsystem, and pass it two conditionals based
# on the host architecture.
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([limits.h stddef.h stdint.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
#AC_TYPE_UINT8_T
#AC_TYPE_UINT16_T
#AC_TYPE_UINT32_T
#AC_TYPE_UINT64_T

dnl If this is a gnu compiler, pass -Wall
if test "$ac_cv_c_compiler_gnu" = "yes"; then
        CFLAGS="$CFLAGS -Wall"
fi

# Checks for library functions.
AC_CHECK_FUNCS([memset strdup strerror])

# Specify the files to generate
#
AC_CONFIG_FILES([Makefile src/Makefile examples/Makefile])
AC_OUTPUT
