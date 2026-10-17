# ExampleModule build
# References shared headers from Branch-main/ (never duplicated).

CC ?= gcc
CXX ?= g++

CFLAGS  = -Wall -Wextra -O2 -I../Branch-main
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -I../Branch-main

.PHONY: all clean

all: example example_cpp

example: example.c
	$(CC) $(CFLAGS) -o $@ $<

example_cpp: example.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f example example_cpp

# branch-ExampleModule/Makefile[∂]
# branch-ExampleModule/Makefile[∂]
