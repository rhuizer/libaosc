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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "getput.h"
#include "x86_ascii.h"
#include "i386_nops.h"
#include "string.h"
#include "wrapper.h"
#include "rand.h"

#define RANGE_MIN	0x21
#define RANGE_MAX	0x7e

#define ALIGN(a, b)	((b) - ((a) % (b)))
#define MAX(a, b)	(((a) > (b)) ? (a) : (b))
#define MIN(a, b)	(((a) < (b)) ? (a) : (b))

/* Prototypes */
static char *__aosc_encode_and_16(char *dst);
static char *__aosc_encode_and_32(char *dst);
static char *__aosc_encode_16(char *, uint16_t, uint16_t);
static char *__aosc_encode_fixed_size_16(char *, uint16_t, uint16_t);
static char *__aosc_encode_32(char *, uint32_t, uint32_t);
static char *__aosc_encode_fixed_size_32(char *, uint32_t, uint32_t);
static struct string *
	__aosc_encode_i386(struct string *, void *, size_t, uint32_t, size_t);
static struct string *
__aosc_encode_x86_64(struct string *dest, void *src, size_t n,
                     uint64_t address, unsigned int nops);
static char *__aosc_backpatch_i386(char *dst, uint32_t esp);
static char *__aosc_backpatch_x86_64(char *dst, uint64_t rsp);
static void __aosc_split_and_8(uint8_t *, uint8_t *);
static void __aosc_split_and_16(uint16_t *, uint16_t *);
static void __aosc_split_and_32(uint32_t *, uint32_t *);
static int __aosc_split_double_sub_32(uint32_t value, uint32_t *a, uint32_t *b);
static void __aosc_split_triple_sub_16(uint16_t, uint16_t *, uint16_t *, uint16_t *);
static void __aosc_split_triple_sub_32(uint32_t, uint32_t *, uint32_t *, uint32_t *);

/* aos_encode() wrapper to make shellcode 'close to segment boundary safe'
 */
char *aosc_encode_32(void *src, size_t n, uint32_t address, size_t nops)
{
	unsigned int j;
	struct string dest;
	size_t n_aligned = n + ALIGN(n, 4) + 4;

	/* Return NULL on arithmetic overflow. */
	if (n > n_aligned)
		return NULL;

	__aosc_encode_i386(&dest, src, n, address, nops);

	for(j = 0; j < n_aligned; j++)
		string_char_append(&dest, rand_uint32_range(0x21, 0x7e), 1);

	/* Hackish, but we return a malloc()ed string to the end-user which
	 * he can free() directly, as to keep the API interface simple.
	 * This means we cannot allow a prefix gap.
	 */
	vector_char_reorder(&dest.data);

	return dest.data.data;
}

char *aosc_encode_64(void *src, size_t n, uint64_t address, size_t nops)
{
	unsigned int j;
	struct string dest;
	size_t n_aligned = n + ALIGN(n, 4) + 4;

	/* Return NULL on arithmetic overflow. */
	if (n > n_aligned)
		return NULL;

	__aosc_encode_x86_64(&dest, src, n, address, nops);

	for(j = 0; j < n_aligned; j++)
		string_char_append(&dest, rand_uint32_range(0x21, 0x7e), 1);

	/* Hackish, but we return a malloc()ed string to the end-user which
	 * he can free() directly, as to keep the API interface simple.
	 * This means we cannot allow a prefix gap.
	 */
	vector_char_reorder(&dest.data);

	return dest.data.data;
}


/** Initialize the code string libaosc uses internally.
 *
 * This function initializes a dynamically scaling string which libaosc
 * uses internally given an original x86 payload.  The result is a string
 * which has been aligned properly and will be used in this library.
 *
 * \param code Pointer to a struct string which will be initialized.
 * \param src Pointer to x86 machine code.
 * \param size Size of the x86 machine code referred to by src.
 */
static void
__aosc_code_init(struct string *code, const char *src, size_t size)
{
	string_init(code);

	/* We pad out the existing shellcode to a 4 byte boundary
	 * Additionaly, we prefix with 4 A's, as to avoid post-nopping
	 * misalignment issues when the decoded payload ends up in the operand
	 * to a multi-byte instruction, and EIP increments after the first
	 * byte of the decoded payload
	 */
	string_set(code, "AAAA");
	string_append(code, src, size);
	string_char_append(code, 'A', ALIGN(size, 4));
}

static struct string *
__aosc_encode_i386(struct string *dest, void *src, size_t n,
                   uint32_t address, size_t nops)
{
	int i;
	uint32_t base;
	char encoded[64];
	struct string code_padded;
	unsigned int backpatch_index;

	rand_init();
	string_init(dest);
	__aosc_code_init(&code_padded, src, n);

	/* Adding pre-nopping with random i386 ASCII only (n)opcodes. */
	aos_nop_engine_init();
	for(i = 0; i < nops; i++)
		string_char_append(dest,
		                   stateful_random_safe_opcode(nops), 1);

	/* Create ASCII only i386 instructions to set eax to 0. */
	__aosc_encode_and_32(encoded);
	string_append(dest, encoded, strlen(encoded));

	/* At this point we want to backpatch values for setting %esp. */
	backpatch_index = string_get_length(dest);

	/* Set eax to 0 once more
	 * XXX: can be evaded if somehow we can fill in the size of the
	 * AO shellcode before encoding, so that return address encoding
	 * needs not be done after everything else.
	 */
	__aosc_encode_and_32(encoded);
	string_append(dest, encoded, strlen(encoded));

	/* Encode the padded shellcode. */
	for(base = 0, i = string_get_length(&code_padded) / 4 - 1; i >= 0; i--) {
		uint32_t value = ((uint32_t *)string_get_data(&code_padded))[i];

		__aosc_encode_32(encoded, base, value);
		base = value;
		string_append(dest, encoded, strlen(encoded));
	}

	/* Now that we know the length of the encoded and decoded payload
	 * we can perform backpatching of the return address.
	 */
	__aosc_backpatch_i386(encoded, address +
	                               string_get_length(&code_padded) +
	                               string_get_length(dest));
	string_insert(dest, backpatch_index, encoded, strlen(encoded));

	/* Adding post-nopping with random i386 ASCII only (n)opcodes. */
	aos_nop_engine_init();
	for(i = 0; i < nops; i++)
		string_char_append(dest, aos_random_post_nop(), 1);

	/* 0-terminate the string before returning it to the user. */
	string_char_append(dest, 0, 1);
	string_destroy(&code_padded);

	return dest;
}

static struct string *
__aosc_encode_x86_64(struct string *dest, void *src, size_t n,
                     uint64_t address, unsigned int nops)
{
	int i;
	uint16_t base;
	char encoded[64];
	struct string code_padded;
	unsigned int backpatch_index;

	rand_init();
	string_init(dest);
	__aosc_code_init(&code_padded, src, n);

	/* Adding pre-nopping with random i386 ASCII only (n)opcodes. */
	aos_nop_engine_init();
	for(i = 0; i < nops; i++)
		string_char_append(dest,
		                   stateful_random_safe_opcode(nops), 1);

	/* Create ASCII only x86_64 instructions to set ax to 0. */
	__aosc_encode_and_16(encoded);
	string_append(dest, encoded, strlen(encoded));

	/* At this point we want to backpatch values for setting %rsp. */
	backpatch_index = string_get_length(dest);

	/* Set ax to 0 once more
	 * XXX: can be evaded if somehow we can fill in the size of the
	 * AO shellcode before encoding, so that return address encoding
	 * needs not be done after everything else.
	 */
	__aosc_encode_and_16(encoded);
	string_append(dest, encoded, strlen(encoded));

	/* Encode the padded shellcode. */
	for(base = 0, i = string_get_length(&code_padded) / 2 - 1; i >= 0; i--) {
		uint16_t value = ((uint16_t *)string_get_data(&code_padded))[i];

		__aosc_encode_16(encoded, base, value);
		base = value;
		string_append(dest, encoded, strlen(encoded));
	}

	/* Now that we know the length of the encoded and decoded payload
	 * we can perform backpatching of the return address.
	 */
	__aosc_backpatch_x86_64(encoded, address +
	                                 string_get_length(&code_padded) +
	                                 string_get_length(dest));
	string_insert(dest, backpatch_index, encoded, strlen(encoded));

	/* Adding post-nopping with random i386 ASCII only (n)opcodes. */
	aos_nop_engine_init();
	for(i = 0; i < nops; i++)
		string_char_append(dest, aos_random_post_nop(), 1);

	/* 0-terminate the string before returning it to the user. */
	string_char_append(dest, 0, 1);
	string_destroy(&code_padded);

	return dest;
}

static char *__aosc_backpatch_i386(char *dst, uint32_t esp)
{
	esp += 16;
	return strcat(__aosc_encode_fixed_size_32(dst, 0, esp), "\x5c");
}

static char *__aosc_backpatch_x86_64(char *dst, uint64_t rsp)
{
	char encoded[64];
	uint16_t word1, word2, word3, word4;

	/* We need to know the size of the backpatched code a priori, and
	 * it needs to be static.
	 */
	rsp += 14 * 4 + 1;

	word1 = rsp >> 48;
	word2 = (rsp >> 32) & 0xFFFF;
	word3 = (rsp >> 16) & 0xFFFF;
	word4 = rsp & 0xFFFF;

	strcpy(dst, __aosc_encode_fixed_size_16(encoded, 0, word1));
	strcat(dst, __aosc_encode_fixed_size_16(encoded, word1, word2));
	strcat(dst, __aosc_encode_fixed_size_16(encoded, word2, word3));
	strcat(dst, __aosc_encode_fixed_size_16(encoded, word3, word4));
	assert(strlen(dst) == 14 * 4);

	return strcat(dst, "\x5c");		/* pop rsp */
}

static char *__aosc_encode_and_16(char *dst)
{
	uint16_t word1, word2;

	__aosc_split_and_16(&word1, &word2);
	dst[0] = 0x66;				/* and ax, 0xXXXX */
	dst[1] = 0x25;
	PUT_16BIT_LSB(&dst[2], word1);
	dst[4] = 0x66;				/* and ax, 0xXXXX */
	dst[5] = 0x25;
	PUT_16BIT_LSB(&dst[6], word2);
	dst[8] = 0;

	return dst;

}

static char *__aosc_encode_and_32(char *dst)
{
	uint32_t dword1, dword2;

	__aosc_split_and_32(&dword1, &dword2);
	dst[0] = 0x25;				/* and eax, 0xXXXXXXXX */
	PUT_32BIT_LSB(&dst[1], dword1);
	dst[5] = 0x25;				/* and eax, 0xXXXXXXXX */
	PUT_32BIT_LSB(&dst[6], dword2);
	dst[10] = 0;

	return dst;
}

/** Encode an uint16_t with a set of x86 ASCII only instructions
 *
 * This function encodes an uint16_t using x86 ASCII only instructions.
 * It yields a sequence of x86 ASCII only instructions which when
 * executed will set eax to the value 'val' and pushing 'val' to the stack,
 * assuming that eax was set to base to begin with.
 *
 * The instructions generated will have the same meaning on both i386 and
 * x86_64.
 *
 * \param dst Pointer to the destination string for the produced sequence.
 * \param base Initial value of eax when starting encoding.
 * \param val Target value pushed to the stack at the end of encoding.
 */
static char *__aosc_encode_16(char *dst, uint16_t base, uint16_t val)
{
	return __aosc_encode_fixed_size_16(dst, base, val);
}

/** Encode an uint32_t with a set of i386 ASCII only instructions
 *
 * This function encodes an uint32_t using i386 ASCII only instructions.
 * It yields a sequence of i386 ASCII only instructions which when
 * executed will set eax to the value 'val' and pushing 'val' to the stack,
 * assuming that eax was set to base to begin with.
 *
 * The instructions generated can be executed only on i386.
 *
 * \param dst Pointer to the destination string for the produced sequence.
 * \param base Initial value of eax when starting encoding.
 * \param val Target value pushed to the stack at the end of encoding.
 */
static char *__aosc_encode_32(char *dst, uint32_t base, uint32_t val)
{
	int ret;
	uint32_t dword1, dword2, dword3;

	/* Try if we can encode this value with two subtractions. */
	ret = __aosc_split_double_sub_32(base - val, &dword1, &dword2);
	if (ret == 0) {
		dst[0] = 0x2d;			/* sub eax, 0xXXXXXXXX */
		PUT_32BIT_LSB(&dst[1], dword1);
		dst[5] = 0x2d;			/* sub eax, 0xXXXXXXXX */
		PUT_32BIT_LSB(&dst[6], dword2);
		dst[10] = 0x50;			/* push eax */
		dst[11] = 0;
		return dst;
	}

	/* If not, we encode if using three subtractions. */
	__aosc_split_triple_sub_32(base - val, &dword1, &dword2, &dword3);
	dst[0] = 0x2d;				/* sub eax, 0xXXXXXXXX */
	PUT_32BIT_LSB(&dst[1], dword1);
	dst[5] = 0x2d;				/* sub eax, 0xXXXXXXXX */
	PUT_32BIT_LSB(&dst[6], dword2);
	dst[10] = 0x2d;				/* sub eax, 0xXXXXXXXX */
	PUT_32BIT_LSB(&dst[11], dword3);
	dst[15] = 0x50;				/* push eax */
	dst[16] = 0;

	return dst;
}

/** Encode an uint16_t with a set of x86 ASCII only instructions
 *
 * This function encodes an uint16_t using x86 ASCII only instructions
 * while making sure the produced sequence is always of the same size.
 * It yields a sequence of x86 ASCII only instructions which when
 * executed will set eax to the value 'val' and pushing 'val' to the stack,
 * assuming that eax was set to base to begin with.
 *
 * The instructions generated will have the same meaning on both i386 and
 * x86-64.
 *
 * \param dst Pointer to the destination string for the produced sequence.
 * \param base Initial value of ax when starting encoding.
 * \param val Target value pushed to the stack at the end of encoding.
 */
static char *__aosc_encode_fixed_size_16(char *dst, uint16_t base, uint16_t val)
{
	uint16_t word1, word2, word3;

	__aosc_split_triple_sub_16(base - val, &word1, &word2, &word3);
	dst[0] = 0x66;				/* sub ax, 0xXXXX */
	dst[1] = 0x2d;
	PUT_16BIT_LSB(&dst[2], word1);
	dst[4] = 0x66;				/* sub ax, 0xXXXX */
	dst[5] = 0x2d;
	PUT_16BIT_LSB(&dst[6], word2);
	dst[8] = 0x66;				/* sub ax, 0xXXXX */
	dst[9] = 0x2d;
	PUT_16BIT_LSB(&dst[10], word3);
	dst[12] = 0x66;				/* push ax */
	dst[13] = 0x50;
	dst[14] = 0;

	return dst;
}

/** Encode an uint32_t with a set of i386 ASCII only instructions
 *
 * This function encodes an uint32_t using i386 ASCII only instructions
 * while making sure the produced sequence is always of the same size.
 * It yields a sequence of i386 ASCII only instructions which when
 * executed will set eax to the value 'val' and pushing 'val' to the stack,
 * assuming that eax was set to base to begin with.
 *
 * The instructions generated can be executed only on i386.
 *
 * \param dst Pointer to the destination string for the produced sequence.
 * \param base Initial value of eax when starting encoding.
 * \param val Target value pushed to the stack at the end of encoding.
 */
static char *__aosc_encode_fixed_size_32(char *dst, uint32_t base, uint32_t val)
{
	uint32_t dword1, dword2, dword3;

	__aosc_split_triple_sub_32(base - val, &dword1, &dword2, &dword3);
	dst[0] = 0x2d;				/* sub eax, 0xXXXXXXXX */
	PUT_32BIT_LSB(&dst[1], dword1);
	dst[5] = 0x2d;				/* sub eax, 0xXXXXXXXX */
	PUT_32BIT_LSB(&dst[6], dword2);
	dst[10] = 0x2d;				/* sub eax, 0xXXXXXXXX */
	PUT_32BIT_LSB(&dst[11], dword3);
	dst[15] = 0x50;				/* push eax */
	dst[16] = 0;

	return dst;
}

static int
__aosc_split_double_sub_32(uint32_t value, uint32_t *a, uint32_t *b)
{
	size_t i;
	int max, min, x;

	*a = *b = 0;

	for(i = 0; i < sizeof(uint32_t); i++) {
		int one_byte;

		one_byte = value >> 24;

		if (one_byte < (RANGE_MIN * 2) || one_byte > (RANGE_MAX * 2))
			return -1;

		max = MAX(RANGE_MIN, one_byte - RANGE_MAX);
		min = MIN(RANGE_MAX, one_byte - RANGE_MIN);

		x = rand_uint32_range(max, min);
		one_byte -= x;

		*a = (*a << 8) + x;
		*b = (*b << 8) + one_byte;
		value <<= 8;
	}

	return 0;
}

static void
__aosc_split_triple_sub_16(uint16_t value,
                           uint16_t *a, uint16_t *b, uint16_t *c)
{
	int i;

	*a = *b = *c = 0;

	for(i = 0; i < sizeof(uint16_t); i++) {
		uint8_t max, min;
		uint16_t x, y, one_byte;

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

		*a += x << (8 * i);
		*b += y << (8 * i);
		*c += one_byte << (8 * i);
		value >>= 8;
	}
}

static void
__aosc_split_triple_sub_32(uint32_t value,
                           uint32_t *a, uint32_t *b, uint32_t *c)
{
	int i;

	*a = *b = *c = 0;

	for(i = 0; i < sizeof(uint32_t); i++) {
		uint16_t one_byte;
		uint8_t x, y, max, min;

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

		*a += x << (8 * i);
		*b += y << (8 * i);
		*c += one_byte << (8 * i);
		value >>= 8;
	}
}

/** Create two random ASCII bytes, which produce zero when and-ed together.
 *
 * This function produces two random bytes, with the additional
 * constraints that the logical AND of these bytes gives a result of zero,
 * and that these bytes fall within the range [0x21, 0x7e].
 *
 * \param byte1 Pointer to the first byte produced.
 * \param byte2 Pointer to the second byte produced.
 */
static void
__aosc_split_and_8(uint8_t *byte1, uint8_t *byte2)
{
	if (rand_uint32_range(1, 255) <= 127) {
		*byte1 = 0x20 | rand_uint32_range(1, 0x1F);
		*byte2 = 0x40 | (rand_uint32_range(0, 0x1F) & ~*byte1);
	} else {
		*byte2 = 0x20 | rand_uint32_range(1, 0x1F);
		*byte1 = 0x40 | (rand_uint32_range(0, 0x1F) & ~*byte2);
	}
}

/** Create two random ASCII words, which produce zero when and-ed together.
 *
 * This function produces two random words, with the additional
 * constraints that the logical AND of these bytes gives a result of zero,
 * and that every byte in these words falls within the range [0x21, 0x7e].
 *
 * \param word1 Pointer to the first word produced.
 * \param word2 Pointer to the second word produced.
 */
static void
__aosc_split_and_16(uint16_t *word1, uint16_t *word2)
{
	size_t i;
	uint8_t *__word1 = (uint8_t *)word1;
	uint8_t *__word2 = (uint8_t *)word2;

	for (i = 0; i < sizeof(uint16_t); i++)
		__aosc_split_and_8(__word1 + i, __word2 + i);
}

/** Create two random ASCII dwords, which produce zero when and-ed together.
 *
 * This function produces two random dwords, with the additional
 * constraints that the logical AND of these bytes gives a result of zero,
 * and that every byte in these words falls within the range [0x21, 0x7e].
 *
 * \param dword1 Pointer to the first dword produced.
 * \param dword2 Pointer to the second dword produced.
 */
static void
__aosc_split_and_32(uint32_t *dword1, uint32_t *dword2)
{
	size_t i;
	uint8_t *__dword1 = (uint8_t *)dword1;
	uint8_t *__dword2 = (uint8_t *)dword2;

	for (i = 0; i < sizeof(uint32_t); i++)
		__aosc_split_and_8(__dword1 + i, __dword2 + i);
}
