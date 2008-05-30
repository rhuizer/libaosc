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
#ifndef I386_NOPS_H
#define I386_NOPS_H

#include <stdbool.h>
#include "i386_opcode.h"

#ifdef __cplusplus
  extern "C" {
#endif

#define safe	true
#define unsafe	false

typedef struct {
	i386_opcode_t opcode;
	bool safety;
	unsigned int size;
} i386_instruction_t;

typedef struct {
	i386_instruction_t *i;
	size_t s;
} i386_iset;

void aos_nop_engine_init(void);
bool safe_unsafe_instr(i386_instruction_t, unsigned int);
inline unsigned char random_safe_opcode(void);
unsigned char stateful_random_safe_opcode(unsigned int);

inline i386_instruction_t aos_random_nop(i386_iset);
unsigned char aos_random_post_nop(void);
i386_instruction_t aos_random_safe_nop(i386_iset);
i386_instruction_t aos_random_unsafe_nop(i386_iset);
i386_instruction_t aos_random_range_nop(i386_iset, unsigned int, unsigned int);

inline i386_iset aos_set_jmp(i386_iset);
i386_iset aos_set_nojmp(i386_iset);
i386_iset aos_set_safe(i386_iset);
i386_iset aos_set_unsafe(i386_iset);

i386_iset aos_set_range(i386_iset, unsigned int, unsigned int);
i386_iset aos_set_size(i386_iset, unsigned int);
i386_iset aos_set_add(i386_iset, i386_instruction_t);
i386_iset aos_set_subtract(i386_iset, i386_iset);

void aos_set_print(i386_iset);

inline i386_iset aos_set_alloc(size_t);
inline i386_iset aos_set_realloc(i386_iset *, size_t);
inline void aos_set_free(i386_iset l);

#ifdef __cplusplus
  }
#endif

#endif
