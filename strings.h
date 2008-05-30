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
#ifndef LIB_STRINGS_H
#define LIB_STRINGS_H

#ifdef __cplusplus
  extern "C" {
#endif

char *str_prepend_char(char *, char, unsigned int);
char *str_prepend_str(char *, char *, unsigned int);
char *str_append_char(char *, char, unsigned int);

char *str_chomp(char *);
char *str_delete_set_prefix(char *, char *);
char *str_delete_set_postfix(char *, char *);
char *str_delete_set_duplicates(char *, char *);
char *str_delete_str_first(char *, char *);
char *str_delete_str_all(char *, char *);
int str_case_cmp(const char *, const char *);

#ifdef __cplusplus
  }
#endif

#endif
