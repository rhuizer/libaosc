/* libaosc, an encoding library for randomized i386 ASCII-only shellcode.
 *
 * Dedicated to Kanna Ishihara.
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
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "i386_ascii.h"
#include "i386_nops.h"
#include "string.h"
#include "wrapper.h"
#include "rand.h"

#define RANGE_MIN	0x21
#define RANGE_MAX	0x7e

#define ALIGN(a, b)	((b) - ((a) % (b)))

#define MAX(a, b)	(((a) > (b)) ? (a) : (b))
#define MIN(a, b)	(((a) < (b)) ? (a) : (b))

/*
 * aos_encode() wrapper to make shellcode 'close to segment boundary safe'
 */
/*
shellcode_t aos_encode_safe(shellcode_t s, void *ra, unsigned int nops)
{
	unsigned int j;
	shellcode_t foo;
	
	foo = aos_encode(s, ra, nops);

	for(j = 0; j < s.size + ALIGN(s.size, 4) + 4; j++) {
		foo.shellcode = (unsigned char *)
			str_append_char((char *)foo.shellcode,
		                (char)xrandom_range(0x21, 0x7e), 1);
		foo.size++;
	}
	return foo;
}
*/

struct string *
aos_encode(struct string *dest, shellcode_t input_code, void *ra, unsigned int nops)
{
	int base, i, j = 0, k;
	int *ret_addy_stuffer[3];
	unsigned int backpatch_index;
	uint32_t __ra = (uint32_t) ra;
	operation_tuple_t *operations;
	tuple_dword and_values;
	int a, b, c;
	struct string code_padded;

	rand_init();
	string_init(&code_padded);
	string_init(dest);

	/* We pad out the existing shellcode to a 4 byte boundary
	 * Additionaly, we prefix with 4 A's, as to avoid post-nopping
	 * misalignment issues when the decoded payload ends up in the operand
	 * to a multi-byte instruction, and EIP increments after the first
	 * byte of the decoded payload
	 */
	string_set(&code_padded, "AAAA");
	string_append(&code_padded, (char *) input_code.shellcode, input_code.size);
	string_char_append(&code_padded, 'A', ALIGN(input_code.size, 4));

	/* Adding pre-nopping with random i386 ASCII only (n)opcodes. */
	aos_nop_engine_init();
	for(i = 0; i < nops; i++)
		string_char_append(dest,
		                   stateful_random_safe_opcode(nops), 1);

	/* Create ASCII only i386 instructions to set eax to 0. */
	and_values = aos_generate_and_zero_dwords();
	string_char_append(dest, ANDI_EAX, 1);
	string_append(dest, (char *) &and_values.dword1, 4);
	string_char_append(dest, ANDI_EAX, 1);
	string_append(dest, (char *) &and_values.dword2, 4);

	/* At this point we want to backpatch values for setting %esp. */
	backpatch_index = string_get_length(dest);
	string_char_append(dest, PUSH + EAX, 1);
	string_char_append(dest, POP + ESP, 1);

	/* Set eax to 0 once more
	 * XXX: can be evaded if somehow we can fill in the size of the
	 * AO shellcode before encoding, so that return address encoding
	 * needs not be done after everything else.
	 */
	and_values = aos_generate_and_zero_dwords();
	string_char_append(dest, ANDI_EAX, 1);
	string_append(dest, (char *) &and_values.dword1, 4);
	string_char_append(dest, ANDI_EAX, 1);
	string_append(dest, (char *) &and_values.dword2, 4);

	/* Encode the padded shellcode. */
	for(base = 0, i = string_get_length(&code_padded) / 4 - 1; i >= 0; i--) {
		operations = aos_encode_dword(base,
			((uint32_t *)string_get_data(&code_padded))[i]);
		base = ((uint32_t *)string_get_data(&code_padded))[i];

		for(k = 0; k < 3; k++) {
			if(operations[k].op == NONE)
				break;
			string_char_append(dest, SUBI_EAX, 1);
			string_append(dest, (char *) &operations[k].value, 4);
		}
		string_char_append(dest, PUSH + EAX, 1);
		free(operations);
	}


	/* Adding post-nopping with random i386 ASCII only (n)opcodes. */
	aos_nop_engine_init();
	for(i = 0; i < nops; i++)
		string_char_append(dest, aos_random_post_nop(), 1);

	/* Fill in the return address placeholders.
	 * NOTE: we SUBTRACT 'nops' since it got added twice to
	 *       garbled_code.size
	 */
	aos_split_triple_sub(
		0 - (__ra + string_get_length(&code_padded) + string_get_length(dest) - nops),
		&a, &b, &c
	);
	string_insert(dest, backpatch_index, (char *) &c, 4);
	string_char_insert(dest, backpatch_index, SUBI_EAX, 1);
	string_insert(dest, backpatch_index, (char *) &b, 4);
	string_char_insert(dest, backpatch_index, SUBI_EAX, 1);
	string_insert(dest, backpatch_index, (char *) &a, 4);
	string_char_insert(dest, backpatch_index, SUBI_EAX, 1);

	string_destroy(&code_padded);
	return dest;
}


/*  This routine manages the encoding of one 32-bit dword in n-ary tuples
 *  of sub/xor/and combinations using bytes in the range of 0x20 to 0x7F,
 *  where 'n' will vary between 1 and 3.
 *  A 3-ary tuple of sub operations using 0x20-0x7F operands is mathematically
 *  complete for what we want to do.
 */
operation_tuple_t *aos_encode_dword(unsigned int base, unsigned int val)
{
	operation_tuple_t *operations;
	unsigned int i;

	operations = (operation_tuple_t *)
				xmalloc(sizeof(operation_tuple_t) * 3);

	for(i = 0; i < 3; i++)
		operations[i].op = NONE;

	if(aos_split_double_sub(base - val, &operations[0].value,
						&operations[1].value)) {
		operations[0].op = operations[1].op = SUB;
		return(operations);
	}

	operations[0].op = operations[1].op = operations[2].op = SUB;
	aos_split_triple_sub(base - val, &operations[0].value,
				&operations[1].value, &operations[2].value);

	return(operations);
}

void aos_print_operation_tuple(operation_tuple_t tuple)
{
	char *type;

	switch(tuple.op) {
	case NONE:
		type = "NONE";
		break;
	case AND:
		type = "AND";
		break;
	case SUB:
		type = "SUB";
		break;
	case XOR:
		type = "XOR";
		break;
	default:
		type = "UNKNOWN";
	}

	printf("%s 0x%.8x\n", type, tuple.value);
}

bool aos_split_double_sub(int value, int *a, int *b)
{
	int i, max, min, x;

	*a = *b = 0;

	for(i = 0; i < 4; i++) {
		int one_byte;

		one_byte = (value & 0x7F000000) / 0x1000000;
		if(value < 0)
			one_byte += 128;

		if(one_byte < (RANGE_MIN * 2) || one_byte > (RANGE_MAX * 2))
			return (false);

		max = MAX(RANGE_MIN, one_byte - RANGE_MAX);
		min = MIN(RANGE_MAX, one_byte - RANGE_MIN);

		x = rand_uint32_range(max, min);
		one_byte -= x;

		*a = (*a * 0x100) + x;
		*b = (*b * 0x100) + one_byte;
		value *= 0x100;
	}
	return(true);
}

void aos_split_triple_sub(int value, int *a, int *b, int *c)
{
	int i;
	int m = 1;

	*a = *b = *c = 0;

	for(i = 0; i < 4; i++) {
		int one_byte;
		int max, min, x, y;

		one_byte = value & 0xFF;

		if(one_byte < RANGE_MIN * 3)
			one_byte += 0x100;

		value -= one_byte;

		max = MAX(RANGE_MIN, one_byte - RANGE_MAX * 2);
		min = MIN(RANGE_MAX, one_byte - RANGE_MIN * 2);

		x = rand_uint32_range(max, min);
		one_byte -= x;

		max = MAX(RANGE_MIN, one_byte - RANGE_MAX);
		min = MIN(RANGE_MAX, one_byte - RANGE_MIN);
		y = rand_uint32_range(max, min);
		one_byte -= y;

		*a += (x * m);
		*b += (y * m);
		*c += (one_byte * m);
		m *= 0x100;

		if(value < 0)
			value = (value & 0x7FFFFFFF) / 0x100 + 0x800000;
		else
			value /= 0x100;
	}
}

/*  Returns an operation tuple array of 2 which contains AND pairs which
 *  always evaluate to 0
 */
tuple_dword aos_generate_and_zero_dwords(void)
{
	unsigned int i;
	tuple_dword pair = { 0, 0 };

	for (i = 0; i < sizeof(pair.dword1); i++) {
		tuple_byte bytes = aos_generate_and_zero_bytes();

		pair.dword1 |= bytes.byte1 << i * 8;
		pair.dword2 |= bytes.byte2 << i * 8;
	}

	return pair;
}

tuple_byte aos_generate_and_zero_bytes(void)
{
	tuple_byte pair;

	if ( rand_uint32_range(1, 255) <= 127 ) {
		pair.byte1 = 0x20 | rand_uint32_range(1, 0x1F);
		pair.byte2 = 0x40 | (rand_uint32_range(0, 0x1F) & ~pair.byte1);
	} else {
		pair.byte1 = 0x40 | rand_uint32_range(0, 0x1F);
		pair.byte2 = 0x20 | (rand_uint32_range(1, 0x1F) & ~pair.byte1);
	}

	return pair;
}
