CFLAGS = -Wall -g
LFLAGS = -Wall -g
CC = g++

TARGETS = capture


all: $(TARGETS)

.cc.o:
	$(CC) $(CFLAGS) -c -o $@ $<

capture.o:	capture.h type.h glue.h

glue.o:		type.h glue.h

capture:	capture.o glue.o
	$(CC) $(LFLAGS) -o $@ $^ -lpcap


clean:
	rm -f *~ *.o $(TARGETS)