CC	= gcc
CFLAGS	= -Wall -ggdb
TARGETS	= exec_sh_test
LIBS	= -laosc -lm

.c.o:;
	$(CC) $(CFLAGS) -c -o $@ $^

all: $(TARGETS)

$(TARGETS): %: %.o 
	$(CC) $(LDFLAGS) -o $@ $@.o -L.. $(LIBS)

clean:
	rm -f  *~ *.o *.core core $(TARGETS)
