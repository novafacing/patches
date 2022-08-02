CC=clang
CXX=clang++
CFLAGS=-O0 -g -ggdb

all: print_twice.bin

print_twice.bin: print_twice.c
	$(CC) -o $@ $(CFLAGS) $^

.PHONY: clean

clean:
	rm -f *.bin

