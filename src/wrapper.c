/* 
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include "config.h"

#ifdef WRAPPER_NETINET
#include <netinet/in.h>
#endif

int warning(const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vfprintf(stderr, fmt, ap);
	va_end(ap);

	return ret;
}

void fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}

/* Sane malloc implementation which sleeps on ENOMEM for a few times using
 * an exponential increase in sleep time.
 */
void *xmalloc(size_t size)
{
	void *ret;
	unsigned int i = 0, stime = 5;

	/* Make sure realloc and malloc behave consistently. */
	if (size == 0)
		return NULL;

	while ( (ret = malloc(size)) == NULL && i != 6) {
		warning("wrapper.c: xmalloc() failed to allocate."
			"Sleeping %u seconds.\n", stime);
#ifdef HAVE_SLEEP
		sleep(stime);
#endif
		stime *= 2, i++;
	}

	if (ret == NULL)
		fatal("wrapper.c: xmalloc() failed to allocate. Aborting.\n");

	return ret;
}

/* Sane realloc() function */
void *xrealloc(void *ptr, size_t size)
{
	void *ret;
	unsigned int i = 0, stime = 5;

	/* Make sure realloc and malloc behave consistently. */
	if (size == 0) {
		free(ptr);
		return NULL;
	}

	while ( (ret = realloc(ptr, size)) == NULL && i != 6) {
		warning("wrapper.c: xrealloc() failed to allocate."
			"Sleeping %u seconds.\n", stime);
#ifdef HAVE_SLEEP
		sleep(stime);
#endif
		stime *= 2, i++;
	}

	if (ret == NULL)
		fatal("wrapper.c: xrealloc() failed to allocate. Aborting.\n");

	return ret;
}

void xfree(void *ptr)
{
	if (ptr != NULL)
		free(ptr);
}

int xfclose(FILE *fp)
{
	while ( fclose(fp) != 0 ) {
		if (errno == EINTR)
			continue;
		fatal("wrapper.c: xfclose() failed: %s\n", strerror(errno));
	}

	return 0;
}

#ifdef WRAPPER_NETINET

int xsocket(int domain, int type, int protocol)
{
	int ret;

	ret = socket(domain, type, protocol);
	if (ret == -1)
		fatal("wrapper.c: xsocket() failed: %s\n", strerror(errno));
	
	return ret;
}

int xbind(int sockfd, const struct sockaddr *my_addr, socklen_t addrlen)
{
	int ret;

	ret = bind(sockfd, my_addr, addrlen);
	if (ret == -1)
		fatal("wrapper.c: xbind() failed: %s\n", strerror(errno));

	return ret;
}

int xlisten(int sockfd, int backlog)
{
	int ret;

	ret = listen(sockfd, backlog);
	if (ret == -1)
		fatal("wrapper.c: xlisten() failed: %s\n", strerror(errno));

	return ret;
}

int xaccept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int ret;

	ret = accept(sockfd, addr, addrlen);
	if (ret == -1 && errno != EINTR)
		fatal("wrapper.c: xaccept() failed: %s\n", strerror(errno));

	return ret;
}

#endif
