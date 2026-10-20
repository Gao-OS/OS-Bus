CC      ?= gcc
CFLAGS  := $(shell pkg-config --cflags gio-2.0) -Wall -Wextra -O2
LDFLAGS := $(shell pkg-config --libs gio-2.0)

all: external_fixture process_guard

external_fixture: external_fixture.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

process_guard: process_guard.c
	$(CC) -Wall -Wextra -Werror -O2 -o $@ $<

clean:
	rm -f external_fixture process_guard

.PHONY: all clean
