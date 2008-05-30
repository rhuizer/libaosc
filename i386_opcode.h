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
#ifndef I386_OPCODE_H
#define I386_OPCODE_H

typedef enum {
	AL,	CL,	DL,	BL,	AH,	CH,	DH,	BH
} reg8_t;

typedef enum {
	AX,	CX,	DX,	BX,	SP,	BP,	SI,	DI
} reg16_t;

typedef enum {
	EAX,		ECX,		EDX,		EBX,
	ESP,		EBP,		ESI,		EDI
} reg32_t;

/*
typedef enum {
	BX_SI,	BX_DI,	BP_SI,	BP_DI,	SI,	DI,	BP,	BX
} rw_t;
*/

typedef enum {
	AAA = 0x37,		AAS = 0x3F,		DAA = 0x27,
	DAS = 0x2F,		DEC = 0x48,		INC = 0x40,
	POP = 0x58,		POPA = 0x61,		PUSH = 0x50,
	PUSHA = 0x60,		BITS = 0x66,		ADDR = 0x67,
	ANDI_AL = 0x24,		CMPI_AL = 0x3C,		SUBI_AL = 0x2C,
	XORI_AL = 0x34,		ANDI_EAX = 0x25,	CMPI_EAX = 0x3D,
	SUBI_EAX = 0x2D,	XORI_EAX = 0x35,	JC_MIN = 0x70,
	JO = 0x70,		JNO,			JB,
	JAE,			JE,			JNE,
	JBE,			JA,			JS,
	JNS,			JP,			JNP,
	JL,			JGE,			JLE,
	JG,			JC_MAX = JG
} i386_opcode_t;

typedef enum {
	O,		NO,		B,		C = 2,
	NAE = 2,	AE,		NB = 3,		NC = 3,
	E,		Z = 4,		NE,		NZ = 5,
	BE,		NA = 6,		A,		NBE = 7,
	S,		NS,		P,		PE = 10,
	NP,		PO = 11,	L,		NGE = 12,
	GE,		NL = 13,	LE,		NG = 14,
	G,		NLE = 15
} cc_t;

#endif
