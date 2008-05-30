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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include "mt19937.h"
#include "rand.h"

unsigned int xrandom_set(unsigned int *s, unsigned int l) {
	return s[xrandom_range(0, l - 1)];
}

unsigned int xrandom_uint(void) {
	return genrand();
}

void xrandom_init(void) {
	sgenrand(time(NULL));
}

/*
 * Return a random value from the range [l, h]
 */
unsigned int xrandom_range(unsigned int l, unsigned int h)
{
	return (xrandom_uint() % (h - l + 1)) + l;
}
