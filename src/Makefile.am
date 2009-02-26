lib_LTLIBRARIES		= libaosc.la

libaosc_ladir		= ${includedir}/libaosc

libaosc_la_SOURCES	= x86_ascii.c x86_ascii.h i386_nops.c		\
			  i386_nops.h i386_opcode.h mt19937.c mt19937.h	\
			  rand.c rand.h string.c string.h vector.h	\
			  wrapper.c wrapper.h getput.h
libaosc_la_LIBADD	= -lm
libaosc_la_HEADERS	= x86_ascii.h
libaosc_la_CFLAGS	= -ggdb -std=c99
