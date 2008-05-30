/* libaosc, an encoding library for randomized i386 ASCII-only shellcode.
 *
 * Dedicated to Merle Planten.
 *
 * Copyright (C) 2001-2008 Ronald Huizer
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <stdio.h>
#include <stdlib.h>
#include "wrapper.h"

FILE *xfopen(const char *path, const char *mode)
{
	FILE *ret;

	if((ret = fopen(path, mode)) == NULL) {
		perror("fopen()");
		exit(EXIT_FAILURE);
	}
	return(ret);
}

void *xmalloc(size_t size)
{
	void *ptr;

	if((ptr = malloc(size)) == NULL) {
		perror("malloc()");
		exit(EXIT_FAILURE);
	}
	return(ptr);
}

void *xrealloc(void *ptr, size_t size)
{
	void *ptr2;

	if( (ptr2 = realloc(ptr, size)) == NULL && size != 0) {
		perror("realloc()");
		exit(EXIT_FAILURE);
	}
	return(ptr2);
}
