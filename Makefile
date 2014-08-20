CFLAGS = -Wall -g
LFLAGS = -Wall -g
CC = g++

TARGETS = capture


all: $(TARGETS)

.cc.o:
	$(CC) $(CFLAGS) -c -o $@ $<

capture.o:	capture.h glue.h

glue.o:		type.h glue.h ./lib/packetheader.hh ./lib/raw_sock.h ./lib/scionpathinfo.hh


capture:	capture.o glue.o
	$(CC) $(LFLAGS) -o $@ $^ -lpcap -lcrypto -L. -lscion


clean:
	rm -f *~ *.o $(TARGETS)