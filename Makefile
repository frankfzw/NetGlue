CCFLAGS = -Wall -g
LDFLAGS = -Wall -g

TARGETS = capture


all: $(TARGETS)

.cc.o:
	gcc $(CCFLAGS) -c -o $@ $<

capture.o:	capture.h type.h

capture:	capture.o
	gcc $(LDFLAGS) -o $@ $^ -lpcap


clean:
	rm -f *~ *.o $(TARGETS)