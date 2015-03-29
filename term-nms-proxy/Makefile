
DEFS = -DLINUX

LDFLAGS =

PROG = tnp

OBJS = blowfish.o netunit.o nl.o inp.o

CC = cc

CFLAGS = -O2 -g3 -W -Wall -fPIC
# -gstabs+

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) -o $@ $(OBJS) 
	rm *.o
	strip -s $(PROG)

.cpp.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f deps $(PROG) *.o tags *.*~
