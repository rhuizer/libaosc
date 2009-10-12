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
 * Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */
#ifndef I386_NOPS_H
#define I386_NOPS_H

#include <stdbool.h>
#include "i386_opcode.h"

#ifdef __cplusplus
  extern "C" {
#endif

#define SAFE	true
#define UNSAFE	false

struct x86_instruction {
	uint8_t		opcode;
	int		safety;
	size_t		size;
};

struct x86_instruction_set {
	struct x86_instruction	*data;
	size_t			size;
};

void aos_nop_engine_init(void);
unsigned char stateful_random_safe_opcode(unsigned int);

#ifdef __cplusplus
  }
#endif

#endif
