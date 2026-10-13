CC     ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra -std=gnu11
LDLIBS  = -pthread

kvstore: kvstore.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f kvstore

.PHONY: clean
