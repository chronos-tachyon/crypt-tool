#!/usr/bin/make -f

CC ?= gcc
CFLAGS ?= -std=gnu11 -Os -Wall -Werror -fPIE
CPPFLAGS ?= -DPIE
LIBS = -lcrypt

.PHONY: all

all: crypt

crypt: main.c Makefile
	$(CC) $(CFLAGS) $(CPPFLAGS) -o "$@" "$<" $(LIBS)
