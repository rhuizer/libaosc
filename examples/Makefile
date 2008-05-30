CC	= gcc
CFLAGS	= -Wall -ggdb -I ../ -I /opt/libemu/include
TARGETS	= exec_sh_test
LIBS	= -laosc

.c.o:;
	$(CC) $(CFLAGS) -c -o $@ $^

all: $(TARGETS)

$(TARGETS): %: %.o 
	$(CC) $(LDFLAGS) -o $@ $@.o -L.. $(LIBS)

clean:
	rm -f  *~ *.o *.core core $(TARGETS)
