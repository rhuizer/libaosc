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
#include <assert.h>
#include <stdlib.h>
#include "rand.h"
#include "x86_ascii.h"
#include "i386_nops.h"
#include "wrapper.h"

/* aosc_random_nop(): Generate a single randomized nop.
 * aosc_random_nops(): Generate random string of nops.
 * aosc_random
 *
 */

static void __aosc_set_destroy(struct x86_instruction_set *set);
static struct x86_instruction_set *__aosc_set_init(
	struct x86_instruction_set *set, size_t size);
static struct x86_instruction_set *__aosc_set_range(
	struct x86_instruction_set *, struct x86_instruction_set *,
	unsigned int, unsigned int);
static struct x86_instruction_set *__aosc_set_subtract(
	struct x86_instruction_set *, struct x86_instruction_set *,
	struct x86_instruction_set *);
static struct x86_instruction_set *
__aosc_set_resize(struct x86_instruction_set *set, size_t size);


inline struct x86_instruction *
__aosc_random_nop(struct x86_instruction_set *set);
struct x86_instruction_set *
__aosc_set_nojmp(struct x86_instruction_set *result,
                 struct x86_instruction_set *set);
struct x86_instruction_set *
__aosc_set_safe(struct x86_instruction_set *result,
                struct x86_instruction_set *set);

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
#define UNSAFE(x)	(!(x)->safety)

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
static struct x86_instruction x86_instr[] = {
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

static struct x86_instruction_set x86_set = {
	x86_instr,
	sizeof(x86_instr) / sizeof(struct x86_instruction)
};

static size_t curlen;

/* The engine keeps track of the last instruction it generated, and at
 * points selects the next instruction to be used.
 */
static struct x86_instruction *prev_instr = NULL;
static struct x86_instruction *next_instr = NULL;

void aosc_nop_engine_init(void)
{
	curlen = 0;
	prev_instr = next_instr = NULL;
}

/*
 * We cannot use conditional jumps in our post nops, because we do not exactly
 * know where our decoded payload will end up.
 * By prepadding our decoded payload with 4 nops itself, we ensure the use
 * of multi byte instructions (since we avoid opcode misalignment issues)
 * and the use of the addr16 and data16 opcodes.
 */
unsigned char aos_random_post_nop(void)
{
	struct x86_instruction *instr;
	struct x86_instruction_set postnop_set;

	__aosc_set_nojmp(&postnop_set, &x86_set);
	instr = __aosc_random_nop(&postnop_set);
	__aosc_set_destroy(&postnop_set);

	return instr->opcode;
}

/*
 *  We eliminate the bits16 opcode as the last byte, as this fscks up our
 *  first ASCII only shellcode immediate AND instruction.
 */
unsigned char stateful_random_safe_opcode(unsigned int nops)
{
	size_t space = nops - curlen;
	struct x86_instruction *i;

	/* If the next instruction is already known, use that one. */
	if (next_instr != NULL) {
		unsigned char opcode = next_instr->opcode;

		next_instr = NULL;
		curlen++;
		return opcode;
	}

	do {
		i = &x86_set.data[rand_uint32_range(0, x86_set.size - 1)];
	} while(space < i->size || (UNSAFE(i) && !can_use_unsafe_instr(i, nops)));
	curlen++;

	/* Track the last instruction handled by the engine. */
	prev_instr = i;

	return i->opcode;
}

/*
 *  XXX: unsafe opcodes are discarded, perhaps we need to keep them in to
 *       improve randomness, but this will need additional checks.
 *       Should be possible with a backtracking algorithm
 */
int
can_use_unsafe_instr(struct x86_instruction *instr, size_t noplen)
{
	struct x86_instruction_set foo, bar;
	size_t left = noplen - curlen;

	if (left == 0) {
		fprintf(stderr, "The libaosc author fucked up.  Bailing out.\n");
		exit(EXIT_FAILURE);
	}

	switch(instr->opcode) {
	/* BITS and ADDR need to be discarded if they are to be the last
	 * nop before the shellcode starts, as they might modify the meaning.
	 */
	case BITS:
	case ADDR:
		return left != 1;
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
		/* We shouldn't be here if the amount of space we have left
		 * is less than 2 bytes.
		 */
		if (left < 2) {
			fprintf(stderr, "The libaosc author fucked up.  Bailing out.\n");
			exit(EXIT_FAILURE);
		}

		/* Make sure not to accidentally use 16-bit branch targets,
		 * as this will result in a zeroed high 16-bit part.
		 */
		if(prev_instr &&
		   (prev_instr->opcode == ADDR || prev_instr->opcode == BITS))
			return 0;

		/* Determine the valid set of instructions we have left.  The
		 * branch itself takes 2 bytes already.
		 *
		 * XXX: this set will only shrink! optimize!
		 */
		if (__aosc_set_range(&foo, &x86_set, 0, left - 2) == NULL)
			return -1;

		/* If the set is empty, we cannot use a branch, as there is no
		 * branch operand we can follow up with.
		 */
		if (foo.size == 0)
			return 0;

		/* XXX: for now only follup up on branches with a safe
		 * instruction.  This should use a backtracking algorithm.
		 */
		if (__aosc_set_safe(&bar, &foo) == NULL) {
			__aosc_set_destroy(&foo);
			return -1;
		}

		__aosc_set_destroy(&foo);

		if (bar.size == 0) {
			__aosc_set_destroy(&bar);
			return 0;
		}

		/* Enforce the next opcode already, as we know it at this
		 * point anyhow.
		 */
		next_instr = __aosc_random_nop(&bar);

		__aosc_set_destroy(&bar);
		return 1;
	}

	return 0;
}

#if 0
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
#endif

inline struct x86_instruction *
__aosc_random_nop(struct x86_instruction_set *set)
{
	assert(set->size != 0);

	return &set->data[rand_uint32_range(0, set->size - 1)];
}

static inline struct x86_instruction_set *
__aosc_set_jmp(struct x86_instruction_set *result,
               struct x86_instruction_set *set)
{
	return __aosc_set_range(result, set, JC_MIN, JC_MAX);
}

struct x86_instruction_set *
__aosc_set_nojmp(struct x86_instruction_set *result,
                 struct x86_instruction_set *set)
{
	struct x86_instruction_set jumps;

	/* Worst case: we cannot have more jumps on set than its size */
	if (__aosc_set_init(result, set->size) == NULL)
		return NULL;

	/* Determine the set of jump instructions. */
	if (__aosc_set_jmp(&jumps, set) == NULL) {
		__aosc_set_destroy(result);
		return NULL;
	}

	/* And subtract this from the set of instructions. */
	if (__aosc_set_subtract(result, set, &jumps) == NULL) {
		__aosc_set_destroy(result);
		__aosc_set_destroy(&jumps);
		return NULL;
	}

	__aosc_set_destroy(&jumps);
	return result;
}

static struct x86_instruction_set *
__aosc_set_range(struct x86_instruction_set *result,
                 struct x86_instruction_set *set,
                 unsigned int min, unsigned int max)
{
	size_t i, j;

	if (__aosc_set_init(result, set->size) == NULL)
		return NULL;

	for (i = j = 0; i < set->size; i++)
		if (set->data[i].opcode >= min && set->data[i].opcode <= max)
			result->data[j++] = set->data[i];

	return __aosc_set_resize(result, j);
}

struct x86_instruction_set *
__aosc_set_safe(struct x86_instruction_set *result,
                struct x86_instruction_set *set)
{
	size_t i, j;

	if (__aosc_set_init(result, set->size) == NULL)
		return NULL;

	for (i = j = 0; i < set->size; i++)
		if (SAFE(set->data[i]))
			result->data[j++] = set->data[i];

	return __aosc_set_resize(result, j);
}

/* XXX: inefficient, of course this can be improved when we force an
 * ordering in the sets themselves, but I'm too lazy at the moment.
 */
static struct x86_instruction_set *
__aosc_set_subtract(struct x86_instruction_set *result,
                    struct x86_instruction_set *set1,
                    struct x86_instruction_set *set2)
{
	size_t i, j, k;

	if (__aosc_set_init(result, set1->size) == NULL)
		return NULL;

	for (i = k = 0; i < set1->size; i++) {
		for (j = 0; j < set2->size; j++) {
			if (set1->data[i].opcode == set2->data[j].opcode)
				break;
		}

		if (j == set2->size)
			result->data[k++] = set1->data[i];
	}

	return __aosc_set_resize(result, k);
}

struct x86_instruction_set *
__aosc_set_init(struct x86_instruction_set *set, size_t size)
{
	/* On multiplication overflow, return NULL. */
	if (size > SIZE_MAX / sizeof(struct x86_instruction))
		return NULL;

	set->size = size;
	set->data = xmalloc(size * sizeof(struct x86_instruction));
	return set;
}

static void __aosc_set_destroy(struct x86_instruction_set *set)
{
	free(set->data);
}

static struct x86_instruction_set *
__aosc_set_resize(struct x86_instruction_set *set, size_t size)
{
	/* On multiplication overflow, return NULL. */
	if (size > SIZE_MAX / sizeof(struct x86_instruction))
		return NULL;

	set->size = size;
	set->data = xrealloc(set->data,
	                     size * sizeof(struct x86_instruction));
	return set;
}
