# ExampleModule

A minimal example demonstrating how to interact with the MEMD kernel module
using the shared `client.h` / `memd.hpp` interfaces.

## Structure

```
ExampleModule/
├── README.md          # This file
├── Makefile           # Build the example
├── example.c          # C example using client.h
├── example.cpp        # C++ example using memd.hpp
└── example.sh         # Shell script example
```

## Prerequisites

- The MEMD kernel module (`rwbridge.ko`) must be loaded on the target device.
- `client.h` and `memd.hpp` are referenced from `../Branch-main/` (never duplicated).
- A C/C++ compiler targeting the device architecture (aarch64 for Android).

## Building

```sh
# From the ExampleModule directory:
make

# Or compile manually:
gcc -I../Branch-main -o example example.c
g++ -std=c++17 -I../Branch-main -o example_cpp example.cpp
```

## Usage

```sh
# Run the C example
./example

# Run the C++ example
./example_cpp

# Run the shell example
sh example.sh
```

## What the examples demonstrate

1. Opening a connection to the MEMD driver
2. Querying module version and learn status
3. Reading process memory
4. Hiding / unhiding a process
5. Listing processes
6. Clean shutdown

## Notes

- All examples require root privileges on the target device.
- The examples are for educational/demonstration purposes only.
- Shared headers are referenced from `Branch-main/`, never copied.
<!-- branch-ExampleModule/README.md[∂] -->