#!/usr/bin/make -f

CC ?= gcc
CFLAGS ?= -std=gnu11 -Os -Wall -Werror -fPIE
CPPFLAGS ?= -DPIE
LIBS = -lcrypt

.PHONY: all clean

all: crypt-tool

clean:
	rm -f crypt-tool

crypt-tool: main.c Makefile
	$(CC) $(CFLAGS) $(CPPFLAGS) -o "$@" "$<" $(LIBS)
