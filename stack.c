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
#include <string.h>
#include "stack.h"
#include "wrapper.h"

void stack_init(stack_t *s) {
	s->ptr = NULL;
	s->sa = s->s = 0;
}

/*
 * Add an entry 'e' to stack 's', reallocating memory as necessary
 */
stack_t *stack_push(stack_t *s, void *e) {
	if(s->ptr == NULL) {
		s->ptr = xmalloc(1024 * sizeof(void *));
		s->sa = 1024;
	} else if(s->s >= s->sa) {
		s->sa *= 2;
		s->ptr = xrealloc(s->ptr, s->sa * sizeof(void *));
	}
	s->ptr[s->s++] = e;
	return s;
}

/*
 * Pop an element from stack 's'
 */
void *stack_pop(stack_t *s) {
	return s->s > 0 ? s->ptr[--s->s] : NULL;
}

void stack_destroy(stack_t *s) {
	if(s->ptr != NULL)
		free(s->ptr);
	s->sa = s->s = 0;
}
