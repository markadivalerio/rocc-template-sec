CC = riscv64-unknown-elf-gcc
CFLAGS ?= -lm -march=rv64imafdcxcustom
OBJ := $(wildcard *.c)
OBJ := $(OBJ:.c=.rv)

.PHONY: clean all

all: $(OBJ)

%.rv: %.c
	$(CC) -o $@ $< $(CFLAGS)

clean:
	rm -rf $(OBJ)
