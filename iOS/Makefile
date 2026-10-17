# iOS/macOS MEMD client build
# Requires: Xcode or clang

CC ?= clang
CFLAGS = -Wall -Wextra -O2 -I.

.PHONY: all clean

all: memd_client

memd_client: client.h memd_client.c
	$(CC) $(CFLAGS) -o $@ memd_client.c

clean:
	rm -f memd_client

# iOS/Makefile[∂]