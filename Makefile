AR	= ar
CC	= gcc
RANLIB	= ranlib
MKDIR	= mkdir
CP	= cp
TAR	= tar
RM	= rm

VERSION	= 1.0.2
CFLAGS	= -Wall -ggdb -s
TARGET	= libaosc.a
FILES	= x86_ascii.o i386_nops.o wrapper.o string.o \
	  mt19937.o rand.o

.c.o:;
	$(CC) $(CFLAGS) -c -o $@ $^

all: $(TARGET) examples

$(TARGET): $(FILES)
	$(AR) rv $@ $(FILES)
	$(RANLIB) $@

examples: $(TARGET)
	$(MAKE) -C examples/

release:
	$(MAKE) clean
	$(RM) -f libaosc-$(VERSION).tar.gz
	$(MKDIR) /tmp/libaosc-$(VERSION)
	$(CP) -a . /tmp/libaosc-$(VERSION)
	$(RM) -rf /tmp/libaosc-$(VERSION)/.git
	$(TAR) -C /tmp -zcvf libaosc-$(VERSION).tar.gz libaosc-$(VERSION)
	$(RM) -rf /tmp/libaosc-$(VERSION)

clean:
	rm -f  *~ *.o *.core core $(TARGET)
	$(MAKE) -C examples/ clean

.PHONY: all $(TARGET) examples clean
