CC = riscv64-unknown-elf-gcc
CFLAGS ?= 
OBJ := $(wildcard *.c)
OBJ := $(OBJ:.c=.rv)

.PHONY: clean all

all: $(OBJ)

%.rv: %.c
	$(CC) -o $@ $< $(CFLAGS)

clean:
	rm -rf $(OBJ)
