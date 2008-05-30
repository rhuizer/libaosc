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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "wrapper.h"
#include "strings.h"

char *str_prepend_char(char *s, char c, unsigned int num)
{
	char *ptr;
	unsigned int i;

	ptr = xmalloc(strlen(s) + num + 1);
	for(i = 0; i < num; i++)
		*(ptr + i) = c;
	strcpy(ptr + i, s);
	free(s);

	return ptr;
}

char *str_append_char(char *s, char c, unsigned int num)
{
	char *ptr;
	unsigned int i;
	size_t size;

	size = strlen(s);
	s = xrealloc(s, (size + num + 1) * sizeof(char));
	ptr = s + size;

	for(i = 0; i < num; i++)
		*ptr++ = c;
	*ptr = 0;

	return s;
}

char *str_prepend_str(char *s, char *p, unsigned int num)
{
	char *ptr;
	size_t size;
	unsigned int i;

	size = strlen(s) + strlen(p) * num + 1;
	*(ptr = xmalloc(size * sizeof(char))) = 0;

	for(i = 0; i < num; i++)
		strcat(ptr, p);
	strcat(ptr, s);

	free(s);
	return ptr;
}

/*
 *  Deletes a trailing "\r\n" or a trailing "\n" if found
 */

char *str_chomp(char *str)
{
	size_t len;

	if( (len = strlen(str)) == 0)
		return str;

	if(str[len-1] == '\n') {
		if(len > 1 && str[len-2] == '\r') str[len-2] = 0;
		else str[len-1] = 0;
	}
	return(str);
}

/*
 *  Delete any of the characters in 'set' from the start of 'str'
 */

char *str_delete_set_prefix(char *str, char *set)
{
	unsigned int i;
	char *start_ptr, *end_prefix_ptr;

	start_ptr = end_prefix_ptr = str;

	for(i = 0; i < strlen(str) && strchr(set, str[i]); i++)
		end_prefix_ptr++;

	while(*end_prefix_ptr != 0)
		*start_ptr++ = *end_prefix_ptr++;
	*start_ptr = 0;
	return(str);
}

/*
 *  Delete any of the characters in 'set' from the end of 'str'
 */

char *str_delete_set_postfix(char *str, char *set)
{
	char *ptr;

	for(ptr = str + strlen(str); ptr > str && strchr(set, *ptr); ptr--);
	*++ptr = 0;
	return(str);
}

/*
 *  Deletes repeated occurences of any character in 'set' from 'str'
 */

char *str_delete_set_duplicates(char *str, char *set)
{
	unsigned int i;

	for(i = 0; i < strlen(set); i++) {
		char *ptr;
		char tuple[3];

		tuple[0] = tuple[1] = set[i], tuple[2] = 0;

		while( (ptr = strstr(str, tuple)) != NULL) {
			char *end;

			for(end = ++ptr; *end == set[i]; end++);

			while(*end != 0)
				*ptr++ = *end++;
			*ptr = 0;
		}
	}
	return(str);
}

/*
 *  Deletes the first occurence of 'delstr' in 'str
 */

char *str_delete_str_first(char *str, char *delstr)
{
	char *start_ptr, *end_ptr;

	if( (start_ptr = strstr(str, delstr)) == NULL)
		return(str);
	end_ptr = start_ptr + strlen(delstr);

	while(*end_ptr != 0)
		*start_ptr++ = *end_ptr++;

	*start_ptr = 0;
	return(str);
}

/*
 *  Delete all occurences of 'delstr' in 'str'
 */

char *str_delete_str_all(char *str, char *delstr)
{
	char *start_ptr, *end_ptr;

	while( (start_ptr = strstr(str, delstr)) != NULL) {
		end_ptr = start_ptr + strlen(delstr);

		while(*end_ptr != 0)
			*start_ptr++ = *end_ptr++;

		*start_ptr = 0;
	}
	return(str);
}

int str_case_cmp(const char *line1, const char *line2)
{
	size_t len;

	if ( (len = strlen(line1)) != strlen(line2))
		return(0);

	while(len--)
		if (tolower(line1[len]) != tolower(line2[len]))
			return(0);
	return(1);
}
