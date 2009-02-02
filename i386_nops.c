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
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include "i386_ascii.h"
#include "i386_nops.h"
#include "wrapper.h"

/*
 * IDEA: we can use a 'safe' opcode everywhere; safe means that it's operand
 * argument can take any value in the given opcode set at any time in the nop
 * string.
 *
 * NOTE that we MUST make sure the last instruction is in alignment with the
 * shellcode afterwards, or it will crash!(*&!#$*(&!
 *
 * Unsafe opcodes could be memory displacement addressing on %esp (which
 * we assume addresable), or Jcc, which can only be used in forward jumps
 * at specific locations in the nop string.
 */

#define SAFE(x)		((x).safety)
#define UNSAFE(x)	(!(x).safety)

#define IS_JMP(x)	((x) > JC_MIN && (x) < JC_MAX)

/*
 *  These are the one byte i386 instructions we can use as nops.
 *  Everything modifying %esp has been excluded (both push and pop, or
 *  operations taking esp as a register target) since the ASCII shellcode
 *  engine relies on %esp pointing somewhere addressable.
 *
 *  'safe' implies the instruction can be used anywhere as a nop (except
 *  perhaps at the end when alignment is needed) without side effects.
 *  'unsafe' means this is not the case, and wether the instruction can
 *  be used or not should be checked.
 */
static i386_instruction_t const instr[] = {
	{ AAA,		safe,	1 }, { AAS,		safe,	1 },
	{ DAA,		safe,	1 }, { DAS,		safe,	1 },
	{ BITS,		unsafe,	1 }, { ADDR,		unsafe,	1 },
	{ INC + EAX,	safe,	1 }, { INC + ECX,	safe,	1 },
	{ INC + EDX,	safe,	1 }, { INC + EDX,	safe,	1 },
	{ INC + EBX,	safe,	1 }, { INC + EBP,	safe,	1 },
	{ INC + ESI,	safe,	1 }, { INC + EDI,	safe,	1 },
	{ DEC + EAX,	safe,	1 }, { DEC + ECX,	safe,	1 },
	{ DEC + EDX,	safe,	1 }, { DEC + EBX,	safe,	1 },
	{ DEC + EBP,	safe,	1 }, { DEC + ESI,	safe,	1 },
	{ DEC + EDI,	safe,	1 }, { ANDI_AL,		safe,	2 },
	{ CMPI_AL,	safe,	2 }, { SUBI_AL,		safe,	2 },
	{ XORI_AL,	safe,	2 }, { JO,		unsafe,	2 },
	{ JNO,		unsafe, 2 }, { JB,		unsafe, 2 },
	{ JAE,		unsafe, 2 }, { JE,		unsafe, 2 },
	{ JNE,		unsafe, 2 }, { JBE,		unsafe, 2 },
	{ JA,		unsafe, 2 }, { JS,		unsafe, 2 },
	{ JNS,		unsafe, 2 }, { JP,		unsafe, 2 },
	{ JNP,		unsafe, 2 }, { JL,		unsafe, 2 },
	{ JGE,		unsafe, 2 }, { JLE,		unsafe, 2 },
	{ JG,		unsafe, 2 }, { ANDI_EAX,	safe,	5 },
	{ CMPI_EAX,	safe,	5 }, { SUBI_EAX,	safe,	5 },
	{ XORI_EAX,	safe,	5 }
};
static unsigned int const instructions =
			sizeof(instr) / sizeof(i386_instruction_t);

static i386_iset i386_i = {
	(i386_instruction_t *)instr,
	sizeof(instr) / sizeof(i386_instruction_t)
};

static unsigned int curlen;
static i386_opcode_t max_opcode, min_opcode, next_opcode, prev_opcode;
static bool next_opcode_set = false, prev_opcode_set = false;

void aos_nop_engine_init(void)
{
	unsigned int j;

	curlen = 0;
	if(instructions == 0)
		return;

	max_opcode = min_opcode = instr[0].opcode;

	for(j = 1; j < instructions; j++) {
		if(instr[j].opcode > max_opcode)
			max_opcode = instr[j].opcode;
		if(instr[j].opcode < min_opcode)
			min_opcode = instr[j].opcode;
	}
}

/*
 * We cannot use conditional jumps in out post nops, because we do not exactly
 * know where our decoded payload will end up.
 * By prepadding our decoded payload with 4 nops itself, we ensure the use
 * of multi byte instructions (since we avoid opcode misalignment issues)
 * and the use of the addr16 and data16 opcodes.
 */
unsigned char aos_random_post_nop(void)
{
	i386_iset post_s;
	i386_instruction_t instr;

	post_s = aos_set_nojmp(i386_i);
	instr = aos_random_nop(post_s);
	aos_set_free(post_s);

	return instr.opcode;
}

/*
 *  We eliminate the bits16 opcode as the last byte, as this fscks up our
 *  first ASCII only shellcode immediate AND instruction.
 */
unsigned char stateful_random_safe_opcode(unsigned int nops)
{
	i386_instruction_t i;
	unsigned int space = nops - curlen;

	if(next_opcode_set) {
		next_opcode_set = false;
		curlen++;
		return next_opcode;
	}

	do {
		i = instr[rand_uint32_range(0, instructions - 1)];
	} while(space < i.size || (UNSAFE(i) && !safe_unsafe_instr(i, nops)));
	curlen++;

	prev_opcode = i.opcode;
	prev_opcode_set = true;

	return i.opcode;
}

/*
 *  XXX: unsafe opcodes are discarded, perhaps we need to keep them in to
 *       improve randomness, but this will need additional checks.
 *       Should be possible with a backtracking algorithm
 */
bool safe_unsafe_instr(i386_instruction_t i, unsigned int noplen)
{
	unsigned int space = noplen - curlen;

	switch(i.opcode) {
	
	/*
	 * BITS and ADDR need to be discarded if they are to be the last
	 * nop before the shellcode starts, as they might modify the meaning.
	 */
	case BITS:
	case ADDR:
		if(space != 1)
			return true;
		break;

	case JO:
	case JNO:
	case JB:
	case JAE:
	case JE:
	case JNE:
	case JBE:
	case JA:
	case JS:
	case JNS:
	case JP:
	case JNP:
	case JL:
	case JGE:
	case JG:
	case JLE:
/*
 *  Some explanation, this function will never get called with space < 2
 *  from stateful_random_safe_opcode() due to the fact that Jcc are 2 bytes
 *  on theirselves. We assert in case this ever gets called by a different
 *  function.
 *  ADDR and BITS 32/16 bit modeswitches fuck up Jcc's due to the fact the
 *  jump target is truncated to 16 bits with insertion of 00 00 at the MSW.
 *  Finally, two is subtracted from the maximum opcode range, since the
 *  Jcc instruction takes two bytes by itself, and will increment eip already.
 */
		assert(space >= 2);

		if(prev_opcode_set)
			if(prev_opcode == ADDR || prev_opcode == BITS)
				return false;

		if(space >= min_opcode + 2) {
			i386_iset foo, bar;

			foo = aos_set_range(i386_i, min_opcode, space - 2);
			bar = aos_set_safe(foo);

			if(bar.s == 0) {
				aos_set_free(foo);
				aos_set_free(bar);
				return false;
			}

			next_opcode = aos_random_nop(bar).opcode;
			next_opcode_set = true;

			aos_set_free(foo);
			aos_set_free(bar);
			return true;
		}
		break;
	default:
		return false;
	}

	return false;
}

unsigned char *generate_nops(unsigned int noplen)
{
	unsigned char *nops;
	unsigned int i;

	nops = (unsigned char *)xmalloc(noplen + 1);

	for(i = 0; i < noplen; i++)
		nops[i] = stateful_random_safe_opcode(noplen);
	nops[i] = 0;

	return nops;
}

/*
 *  Get a random 'nop' from the instruction list p of size s
 */
inline i386_instruction_t aos_random_nop(i386_iset l)
{
	assert(l.s != 0);

	return l.i[rand_uint32_range(0, l.s - 1)];
}

/*
 *  Get a random safe 'nop' from the list p of size s
 *  This is done by constructing a subset of p with only safe instructions
 */
i386_instruction_t aos_random_safe_nop(i386_iset l)
{
	i386_iset safe_s;
	i386_instruction_t foo;

	safe_s = aos_set_safe(l);
	foo = aos_random_nop(safe_s);
	aos_set_free(safe_s);

	return foo;
}

/*
 *  Get a random unsafe 'nop' from the list p of size s
 *  This is done by constructing a subset of p with only safe instructions
 */
i386_instruction_t aos_random_unsafe_nop(i386_iset l)
{
	i386_iset unsafe_s;
	i386_instruction_t foo;

	unsafe_s = aos_set_unsafe(l);
	foo = aos_random_nop(unsafe_s);
	aos_set_free(unsafe_s);

	return foo;
}

/*
 *  Get a random nop from the list with range [lo..hi]
 */
i386_instruction_t aos_random_range_nop(l, lo, hi)
i386_iset l;
unsigned int lo, hi;
{
	i386_iset range_s;
	i386_instruction_t foo;

	range_s = aos_set_range(l, lo, hi);
	foo = aos_random_nop(range_s);
	aos_set_free(range_s);

	return foo;
}

/*
 * Construct a subset from 'l' with only JC type instructions
 */
inline i386_iset aos_set_jmp(i386_iset l)
{
	return aos_set_range(l, JC_MIN, JC_MAX);
}

/*
 * Construct a subset from 'l' with no JC type instructions
 */
i386_iset aos_set_nojmp(i386_iset l)
{
	i386_iset jmps, nojmps;

	jmps = aos_set_jmp(l);
	nojmps = aos_set_subtract(l, jmps);
	aos_set_free(jmps);
	return nojmps;
}

/*
 * Construct a subset from 'l' where the instruction size equals size
 */
i386_iset aos_set_size(i386_iset l, unsigned int size)
{
	unsigned int i, j;
	i386_iset size_s;

	size_s = aos_set_alloc(l.s);

	for(i = j = 0; i < l.s; i++)
		if(l.i[i].size == size)
			size_s.i[j++] = l.i[i];

	return aos_set_realloc(&size_s, j);
}

/*
 * Construct a subset from 'l' where the opcode is in range [lo, hi]
 */
i386_iset aos_set_range(i386_iset l, unsigned int lo, unsigned int hi)
{
	unsigned int i, j;
	i386_iset range_s;

	range_s = aos_set_alloc(l.s);

	for(i = 0, j = 0; i < l.s; i++)
		if(l.i[i].opcode >= lo && l.i[i].opcode<= hi)
			range_s.i[j++] = l.i[i];

	return aos_set_realloc(&range_s, j);
}

/*
 * Construct a subset from 'l' where the instruction is 'safe'
 */
i386_iset aos_set_safe(i386_iset l)
{
	unsigned int i, j;
	i386_iset safe_s;

	safe_s = aos_set_alloc(l.s);

	for(i = j = 0; i < l.s; i++)
		if(SAFE(l.i[i]))
			safe_s.i[j++] = l.i[i];

	return aos_set_realloc(&safe_s, j);
}

/*
 * Construct a subset from 'l' where the instruction is 'unsafe'
 */
i386_iset aos_set_unsafe(i386_iset l)
{
	unsigned int i, j;
	i386_iset safe_s;

	safe_s = aos_set_alloc(l.s);

	for(i = j = 0; i < l.s; i++)
		if(UNSAFE(l.i[i]))
			safe_s.i[j++] = l.i[i];

        return aos_set_realloc(&safe_s, j);
}

/*
 * Construct a superset of 'l' with addition of 'instr'
 */
i386_iset aos_set_add(i386_iset l, i386_instruction_t instr)
{
	unsigned int i;
	i386_iset add_s;

	add_s = aos_set_alloc(l.s + sizeof(i386_instruction_t));

	for(i = 0; i < l.s; i++)
		add_s.i[i] = l.i[i];
	add_s.i[i] = instr;
	
	return add_s;
}

/*
 * Construct a subset of 'set1' without the any of the elements in 'set2'
 */
i386_iset aos_set_subtract(i386_iset set1, i386_iset set2)
{
	int in_set = 0;
	unsigned int i, j, k;
	i386_iset result_s;

	result_s = aos_set_alloc(set1.s);
	
	for(i = k = 0; i < set2.s; i++) {
		for(j = 0; j < set1.s; j++) {
			if(set1.i[i].opcode == set2.i[j].opcode) {
				in_set = 1;
				break;
			}
		}
		if(!in_set)
			result_s.i[k++] = set1.i[i];
	}
	aos_set_realloc(&result_s, k);

	return result_s;
}

/*
 * Print the contents of set 'l'
 */
void aos_set_print(i386_iset l)
{
	unsigned int i;

	for(i = 0; i < l.s; i++) {
		printf("Entry %u\n", i);
		printf("============================\n");
		printf("OPCODE: %.2x\n", l.i[i].opcode);
		printf("SAFE: %s\n", SAFE(l.i[i]) ? "true" : "false");
		printf("SIZE: %u\n\n", l.i[i].size);
	}
}

/*
 * Allocate a instruction set of size 'size'
 */
inline i386_iset aos_set_alloc(size_t size)
{
	i386_iset l;

	l.s = size;
	size *= sizeof(i386_instruction_t);
	l.i = (i386_instruction_t *)xmalloc(size);
	return l;
}

inline i386_iset aos_set_realloc(i386_iset *i, size_t s)
{
	i->s = s;
	s *= sizeof(i386_instruction_t);
	i->i = (i386_instruction_t *)xrealloc(i->i, s);

	return *i;
}

inline void aos_set_free(i386_iset l)
{
	free(l.i);
}
