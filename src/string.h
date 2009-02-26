/* libaosc, an encoding library for randomized x86 ASCII-only shellcode.
 *
 * Dedicated to Kanna Ishihara.
 *
 * Copyright (C) 2001-2009 Ronald Huizer
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
 * Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */
#ifndef __STRING_H
#define __STRING_H

#include <stdlib.h>
#include "vector.h"

#ifdef __cplusplus
extern "C" {
#endif

VECTOR_DECLARE(char, char);

struct string
{
	struct vector_char	data;
};

struct string *string_init(struct string *string);
void string_destroy(struct string *string);
struct string *string_set(struct string *string, const char *value);
struct string *string_char_insert(struct string *string, unsigned int index,
                                  char c, unsigned int num);
struct string *string_char_prepend(struct string *string, char c,
                                   unsigned int num);
struct string *string_char_append(struct string *string, char c,
                                  unsigned int num);
struct string *string_insert(struct string *string, unsigned int index,
                             const char *p, size_t len);
struct string *string_prepend(struct string *string, char *p, size_t len);
struct string *string_append(struct string *string, const char *p, size_t len);
struct string *string_chomp(struct string *string);
int string_print(struct string *string);
size_t string_get_length(struct string *string);
char *string_get_data(struct string *string);

#ifdef __cplusplus
}
#endif

#endif
