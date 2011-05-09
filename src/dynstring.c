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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "dynstring.h"

VECTOR_DEFINE(char, char);

struct string *
string_init(struct string *string)
{
	vector_char_init(&string->data);
	return string;
}

void
string_destroy(struct string *string)
{
	vector_char_destroy(&string->data);
}

struct string *
string_set(struct string *string, const char *value)
{
	vector_char_destroy(&string->data);
	vector_char_init(&string->data);
	vector_char_add(&string->data, value, strlen(value));

	return string;
}

size_t
string_get_length(struct string *string)
{
	return vector_char_get_size(&string->data);
}

char *
string_get_data(struct string *string)
{
	return (char *) string->data.data + string->data.start;
}

struct string *
string_char_insert(struct string *string, unsigned int index,
                   char c, unsigned int num)
{
	unsigned int i;

	if ( vector_char_create_gap(&string->data, index, num) == NULL )
		return NULL;

	/* We don't need to check for an addition overflow here, as it is
	 * tested internally by vector_char_create_grap() which would
	 * return NULL.
	 */
	for (i = index; i < index + num; i++)
		vector_char_set_element(&string->data, i, c);

	return string;
}

struct string *
string_char_prepend(struct string *string, char c, unsigned int num)
{
	return string_char_insert(string, 0, c, num);
}

struct string *
string_char_append(struct string *string, char c, unsigned int num)
{
	return string_char_insert(string,
	                          vector_char_get_size(&string->data),
				  c, num);
}

struct string *
string_insert(struct string *string, unsigned int index,
              const char *p, size_t len)
{
	unsigned long i;

	if (vector_char_create_gap(&string->data, index, len) == NULL)
		return NULL;

	for (i = index; i < index + len; i++)
		vector_char_set_element(&string->data, i, p[i - index]);

	return string;
}

struct string *
string_prepend(struct string *string, char *p, size_t len)
{
	return string_insert(string, 0, p, len);
}

struct string *
string_append(struct string *string, const char *p, size_t len)
{
	return string_insert(string,
	                     vector_char_get_size(&string->data), p, len);
}

struct string *
string_chomp(struct string *string)
{
	size_t len = vector_char_get_size(&string->data);

	if (len == 0)
		return string;

	if (vector_char_get_element(&string->data, len - 1) == '\n') {
		if (len > 1 && 
		    vector_char_get_element(&string->data, len - 2) == '\r') {
			string->data.end -= 2;
		} else {
			string->data.end--;
		}
	}

	return string;
}

int
string_print(struct string *string)
{
	return printf("%.*s", (int) vector_char_get_size(&string->data),
	                      vector_char_get_element_ptr(&string->data, 0));
}

#if 0
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


int main(void)
{
	struct string s;

	string_init(&s);
	string_set(&s, "foobarbaz\r\n");

	string_chomp(&s);
	string_char_prepend(&s, 'A', 10);

	string_print(&s);
	printf("\n");

	string_destroy(&s);
}
#endif
