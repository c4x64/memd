# Windows MEMD build
# Client: MinGW GCC
# Driver: WDK (msbuild)

CC ?= gcc
CFLAGS = -Wall -O2 -I.

.PHONY: all clean client

all: client

client: client.h memd_client.c
	$(CC) $(CFLAGS) -o memd_client.exe memd_client.c

clean:
	rm -f memd_client.exe

# Windows/Makefile[∂]