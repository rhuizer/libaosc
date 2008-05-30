AR     = ar
CC     = gcc
RANLIB = ranlib
CFLAGS = -Wall -O2 -s
TARGET = libaosc.a
FILES  = i386_ascii.o i386_nops.o wrapper.o strings.o stack.o \
	 mt19937.o rand.o

.c.o:;
	$(CC) $(CFLAGS) -c -o $@ $^

all: $(TARGET) examples

$(TARGET): $(FILES)
	$(AR) rv $@ $(FILES)
	$(RANLIB) $@

examples: $(TARGET)
	$(MAKE) -C examples/

clean:
	rm -f  *~ *.o *.core core $(TARGET)
	$(MAKE) -C examples/ clean

.PHONY: all $(TARGET) examples clean
