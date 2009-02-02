/* libaosc, an encoding library for randomized i386 ASCII-only shellcode.
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#ifndef I386_ASCII_H
#define I386_ASCII_H

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include "string.h"
#include "rand.h"

#ifdef __cplusplus
  extern "C" {
#endif

typedef enum {
	NONE,	AND,	SUB,	XOR
} operation_t;

typedef struct {
	operation_t op;
	int value;
} operation_tuple_t;

struct string *aos_encode_safe(struct string *, void *, size_t, void *, unsigned int);
struct string *aos_encode(struct string *, void *, size_t, void *, unsigned int);
operation_tuple_t *aos_encode_dword(unsigned int, unsigned int);
void aos_print_operation_tuple(operation_tuple_t);
bool aos_split_double_xor(int, int *, int *);
bool aos_split_double_sub(int, int *, int *);
void aos_split_triple_sub(int, int *, int *, int *);
operation_tuple_t *aos_and_zero_pair(void);

void aos_generate_and_zero_dwords(uint32_t *, uint32_t *);
void aos_generate_and_zero_bytes(uint8_t *, uint8_t *);

#ifdef __cplusplus
  }
#endif

#endif
